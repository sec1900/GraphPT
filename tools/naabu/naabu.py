"""naabu wrapper — 直接调 naabu.exe 并输出 JSON，绕过 PipelineExecutor Popen。"""
import subprocess, sys, os, json

def main():
    args = sys.argv[1:]
    # 把 tool.yaml 风格的参数转成 naabu 原生参数
    naabu_args = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-list" and i+1 < len(args):
            naabu_args.extend(["-list", args[i+1]]); i += 2
        elif a == "-host" and i+1 < len(args):
            naabu_args.extend(["-host", args[i+1]]); i += 2
        elif a == "-tp":
            naabu_args.extend(["-tp", args[i+1]]); i += 2
        elif a == "-p":
            naabu_args.extend(["-p", args[i+1]]); i += 2
        elif a in ("-silent", "-json"):
            naabu_args.append(a); i += 1
        else:
            naabu_args.append(a); i += 1

    _TOOLS = os.path.dirname(os.path.abspath(__file__))
    naabu_bin = os.path.join(_TOOLS, "naabu.exe")

    proc = subprocess.Popen([naabu_bin] + naabu_args,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, encoding="utf-8", errors="replace")
    stdout, _ = proc.communicate(timeout=120)
    sys.stdout.write(stdout)
    sys.exit(proc.returncode)

if __name__ == "__main__":
    main()
