# add() 함수 하나로 해보는 리버싱 튜토리얼

`int add(int x, int y)` 라는 아주 단순한 함수 하나를 만들어서, Ghidra로
뜯어보고 Frida로 실행 중에 값을 바꿔치기해보는 실습입니다.

## 준비물

```bash
sudo apt-get install gcc binutils     # 컴파일러랑 objdump/nm/strip
python3 -m venv venv
./venv/bin/pip install frida frida-tools
```

Ghidra는 headless 모드(`analyzeHeadless`)로만 씁니다. GUI 안 켜도 됩니다.

## 1. 일단 만들고 실행해보기

```bash
gcc -O0 -fno-omit-frame-pointer -o main main.c
./main
# add(3, 4) = 7
```

## 2. Ghidra로 add() 찾아보기

바이너리만 보고 `add()`가 어디 있는지, 뭘 하는지 Ghidra가 알아서
찾아내게 합니다.

```bash
mkdir -p ghidra_proj
~/opt/ghidra/support/analyzeHeadless \
  ghidra_proj MainProj -import ./main \
  -scriptPath ./scripts -postScript DumpAdd.java -overwrite
```

로그 마지막쯤에 이런 게 나오면 성공입니다.

```
Found function: add at 00101139
int add(int param_1,int param_2)
{
  return param_2 + param_1;
}
```

`0x1139`가 바로 `add()`의 위치예요. 이 주소는 나중에 후킹이 다른 방법으로
안 될 때 최후의 수단으로 씁니다.

## 3. Frida로 후킹해서 값 바꿔치기

```bash
./venv/bin/python run_hook.py ./main
```

`hook.js`가 하는 일은 크게 두 가지입니다.

**첫째, add()가 어디 있는지 찾기.** 이름으로 찾아보고, 안 되면 함수의
실제 바이트(기계어)를 패턴으로 스캔해서 찾고, 그것도 안 되면 아까 Ghidra가
알려준 주소를 그냥 씁니다.

**둘째, 찾은 곳을 후킹하기.** `Interceptor.attach`로 함수 시작 부분에
걸어서, 들어오는 인자(`x`, `y`)를 가로채 `100`, `200`으로 바꿔치기하고,
나갈 때 원래 계산된 반환값(`300`)도 `9999`로 바꿔서 내보냅니다.

실행해보면 이렇게 나옵니다.

```
add(3, 4) = 9999
[hook] add() called with original x=3, y=4
[hook] arguments overwritten -> x=100, y=200
[hook] add(100, 200) originally returned 300
[hook] return value overwritten -> 9999
```

## 4. strip해도 되는지 확인

```bash
cp main main_stripped && strip --strip-all main_stripped
./venv/bin/python run_hook.py ./main_stripped
```

`strip`을 하면 심볼(함수 이름 정보)이 다 지워지는데, 그래도 됩니다.
이름으로 못 찾으면 바이트 패턴으로 찾도록 만들어놨거든요.

## 5. 최적화(-O2)를 걸면 무슨 일이 생기나

```bash
gcc -O2 -fno-omit-frame-pointer -o main_rt main_rt.c
./venv/bin/python run_hook.py ./main_rt
```

최적화를 켜면 컴파일러가 `add()`를 4바이트짜리(`lea eax,[rdi+rsi]; ret`)
로 확 줄여버립니다. 이러면 재밌는 문제가 생기는데, Frida가 후킹하려면
함수 시작 부분에 점프 코드를 심어야 하는데 그 점프 코드 자체가 5바이트라
**함수보다 커서 못 심습니다.** ("함수가 너무 작아서 후킹이 안 되는" 상황)

그래서 `add()` 자체를 후킹하는 대신, `add()`를 **호출하는 곳**
(`main()` 안의 `call add`)을 찾아서 그 앞뒤를 가로챕니다. `main()`은
충분히 크니까요.

```
[!] direct hook failed (...) - falling back to call-site hooking
[*] found call site: call @ 0x...06c, returns to 0x...071
[*] hook installed via call-site interception
```

참고로 `main_rt.c`에는 컴파일러가 `add(3, 4)`를 아예 계산해서 지워버리지
못하게 막는 트릭이 두 개 들어있습니다 (`volatile`로 상수 계산 방지,
`noinline`으로 함수를 통째로 안으로 합쳐버리는 것 방지). 이게 없으면
`call add` 자체가 사라져서 호출부 후킹도 손 쓸 방법이 없어집니다.

## 결국 뭘 배웠냐면

- 함수 이름이 없어도(strip) 바이트 패턴으로 찾을 수 있다.
- 함수가 너무 작으면 직접 후킹은 아예 안 될 수 있다.
- 그럴 땐 함수를 호출하는 곳을 대신 후킹하면 된다.
- 단, 컴파일러가 그 호출 자체를 지워버렸다면(상수 계산, 인라인) 그마저도
  안 통한다 — 이럴 땐 애초에 후킹할 대상이 바이너리에 없는 것.

## 직접 해보기

`hook.js` 맨 위에 있는 `NEW_X`, `NEW_Y`, `FAKE_RET` 숫자를 원하는 값으로
바꾸고 다시 실행해보세요.

```bash
./venv/bin/python run_hook.py ./main               # -O0, 직접 후킹
./venv/bin/python run_hook.py ./main_stripped
./venv/bin/python run_hook.py ./main_rt             # -O2, 호출부 후킹
./venv/bin/python run_hook.py ./main_rt_stripped
```
