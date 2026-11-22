"""Create a clean source archive; never bundle model weights, logs, or environment."""
from pathlib import Path
import argparse
import hashlib
import zipfile

ROOT=Path(__file__).resolve().parents[1]
EXCLUDED={"data","models",".venv","runtime",".git",".pytest_cache","__pycache__"}

def main():
    parser=argparse.ArgumentParser();parser.add_argument("output",type=Path);args=parser.parse_args()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    files=[]
    for path in sorted(ROOT.rglob("*")):
        relative=path.relative_to(ROOT)
        if not path.is_file() or any(part in EXCLUDED or part.endswith(".egg-info") for part in relative.parts):continue
        if path.suffix in {".pyc",".gguf"}:continue
        files.append((path,relative))
    hashes="\n".join(hashlib.sha256(path.read_bytes()).hexdigest()+"  "+str(relative).replace('\\','/') for path,relative in files)+"\n"
    with zipfile.ZipFile(args.output,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path,relative in files:archive.write(path,Path("local-soc-assistant")/relative)
        archive.writestr("local-soc-assistant/SHA256SUMS.txt",hashes)
    print(f"{args.output}: {len(files)} files, {args.output.stat().st_size} bytes")

if __name__=="__main__":main()
