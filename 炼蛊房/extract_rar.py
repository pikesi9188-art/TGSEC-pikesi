#!/usr/bin/env python3
"""临时解压工具"""
import rarfile
import sys
import os

def extract_rar(rar_path, extract_to):
    """解压 RAR 文件"""
    try:
        # 尝试设置 unrar 路径
        possible_paths = [
            '/usr/local/bin/unrar',
            '/usr/bin/unrar',
            '/opt/homebrew/bin/unrar',
            'unrar'
        ]

        rf = rarfile.RarFile(rar_path)
        rf.extractall(extract_to)
        print(f"✓ 解压完成到: {extract_to}")

        # 列出解压的文件
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                filepath = os.path.join(root, file)
                print(f"  - {filepath}")

    except rarfile.NeedFirstVolume:
        print("错误: 需要第一个分卷")
        sys.exit(1)
    except rarfile.BadRarFile:
        print("错误: 不是有效的 RAR 文件")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <rar文件> <解压目录>")
        sys.exit(1)

    extract_rar(sys.argv[1], sys.argv[2])
