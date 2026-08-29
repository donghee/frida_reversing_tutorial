/*
 * Hooks add(int, int) in the running process, overrides its arguments and
 * return value, and logs both. Handles three real-world obstacles in order:
 *   1. add() may not be a dynamic export -> resolve it by name/pattern/offset.
 *   2. add() may be too small to patch directly -> hook its call site instead.
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const NEW_X = 100;
const NEW_Y = 200;
const FAKE_RET = 9999;

const KNOWN_OFFSET = 0x1139; // last-resort fallback, from an earlier Ghidra analysis

// Exact instruction bytes of add(int,int){return x+y;}, one per optimization
// level seen so far. A single signature is fragile across compiler settings.
const ADD_PATTERNS = [
    "55 48 89 e5 89 7d fc 89 75 f8 8b 55 fc 8b 45 f8 01 d0 5d c3", // -O0
    "8d 04 37 c3",                                                 // -O2
];

// ---------------------------------------------------------------------------
// Step 1: resolve add()'s address
// ---------------------------------------------------------------------------

function findByName(mod) {
    // Only works if add() is still in the (non-stripped) static symbol table -
    // it's a local symbol, so Module.getExportByName() can never see it.
    const sym = mod.enumerateSymbols().find(s => s.name === "add");
    return sym ? sym.address : null;
}

function findByPattern(mod) {
    for (const pattern of ADD_PATTERNS) {
        for (const range of mod.enumerateRanges("r-x")) {
            const match = Memory.scanSync(range.base, range.size, pattern)[0];
            if (match) return match.address;
        }
    }
    return null;
}

function resolveAddAddress(mod) {
    const strategies = [
        ["name", findByName],
        ["byte-pattern scan", findByPattern],
        ["known offset", m => m.base.add(KNOWN_OFFSET)],
    ];
    for (const [label, find] of strategies) {
        const addr = find(mod);
        if (addr) {
            send(`[*] add() resolved via ${label} @ ${addr}`);
            return addr;
        }
    }
    throw new Error("could not resolve add()");
}

// ---------------------------------------------------------------------------
// Step 2: hook it - directly, or via its call site if it's too small to patch
// ---------------------------------------------------------------------------

function hookCallee(addAddr) {
    Interceptor.attach(addAddr, {
        onEnter(args) {
            send(`[hook] add() called with original x=${args[0].toInt32()}, y=${args[1].toInt32()}`);
            args[0] = ptr(NEW_X);
            args[1] = ptr(NEW_Y);
            send(`[hook] arguments overwritten -> x=${NEW_X}, y=${NEW_Y}`);
        },
        onLeave(retval) {
            send(`[hook] add(${NEW_X}, ${NEW_Y}) originally returned ${retval.toInt32()}`);
            retval.replace(ptr(FAKE_RET));
            send(`[hook] return value overwritten -> ${FAKE_RET}`);
        }
    });
    send("[*] hook installed via Interceptor.attach (on the callee itself)");
}

// Finds the first `call` instruction targeting targetAddr in mod's executable
// ranges. Returns its own address (args still in registers) and the address
// right after it (return value now in rax).
function findCallSite(mod, targetAddr) {
    for (const range of mod.enumerateRanges("r-x")) {
        let addr = range.base;
        const end = range.base.add(range.size);
        while (addr.compare(end) < 0) {
            let insn;
            try {
                insn = Instruction.parse(addr);
            } catch (e) {
                addr = addr.add(1);
                continue;
            }
            if (insn.mnemonic === "call" && /^0x[0-9a-f]+$/i.test(insn.opStr) && ptr(insn.opStr).equals(targetAddr)) {
                return { callAddr: insn.address, returnAddr: insn.next };
            }
            addr = insn.next;
        }
    }
    return null;
}

function hookCallSite(mod, addAddr) {
    const site = findCallSite(mod, addAddr);
    if (!site) {
        throw new Error("no call site found (function may be dead code / inlined away)");
    }
    send(`[*] found call site: call @ ${site.callAddr}, returns to ${site.returnAddr}`);

    // SysV x86-64: at the call, args are in rdi/rsi; right after it returns, rax holds the result.
    Interceptor.attach(site.callAddr, function () {
        send(`[callsite] about to call add() with original x=${this.context.rdi.toInt32()}, y=${this.context.rsi.toInt32()}`);
        this.context.rdi = ptr(NEW_X);
        this.context.rsi = ptr(NEW_Y);
        send(`[callsite] arguments overwritten -> x=${NEW_X}, y=${NEW_Y}`);
    });
    Interceptor.attach(site.returnAddr, function () {
        send(`[callsite] add(${NEW_X}, ${NEW_Y}) returned ${this.context.rax.toInt32()}`);
        this.context.rax = ptr(FAKE_RET);
        send(`[callsite] return value overwritten -> ${FAKE_RET}`);
    });
    send("[*] hook installed via call-site interception");
}

function hookAdd(mod, addAddr) {
    // add() is often just a few bytes (e.g. `lea eax,[rdi+rsi]; ret` at -O2),
    // too small for Interceptor.attach's inline trampoline. Fall back to
    // hooking its (much larger) caller at the call instruction instead.
    try {
        hookCallee(addAddr);
        return;
    } catch (e) {
        send(`[!] direct hook failed (${e.message}) - falling back to call-site hooking`);
    }

    try {
        hookCallSite(mod, addAddr);
    } catch (e) {
        send(`[!] call-site hooking failed (${e.message}) - giving up`);
    }
}

// ---------------------------------------------------------------------------

const mod = Process.mainModule;
send(`[*] module base = ${mod.base}`);
hookAdd(mod, resolveAddAddress(mod));
