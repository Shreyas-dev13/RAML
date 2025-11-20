import os
import tempfile
import subprocess

import xml.etree.ElementTree as ET

from .raml.main import SmaliMalwareAnalyzer
from ..celery import schedule_task


@schedule_task
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

    try:
        subprocess.run(decode_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}:")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
    
    package_name = get_package_name(smali_output)
    analyzer = SmaliMalwareAnalyzer(smali_folder=smali_output, package_name=package_name)
    await analyzer.setup_system(force_rebuild=False)
    return await analyzer.analyze_behaviors(list(range(1, 13)))


def get_package_name(apktool_output_dir):
    """Extract package name from AndroidManifest.xml"""
    manifest_path = os.path.join(apktool_output_dir, "AndroidManifest.xml")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    return root.attrib['package']
