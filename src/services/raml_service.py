import tempfile
import subprocess
from .raml.main import SmaliMalwareAnalyzer


async def analyze_apk_with_raml(apk_path: str):
    smali_output = tempfile.mkdtemp(prefix="smali_code")

    decode_cmd = [
        "apktool",
        "decode",
        apk_path,
        "-o",
        smali_output,
        "-f"
    ]

    subprocess.run(decode_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    analyzer = SmaliMalwareAnalyzer(smali_folder=smali_output)
    await analyzer.setup_system(force_rebuild=False)
    return await analyzer.analyze_behaviors(list(range(1, 13)))
