"""
OpenClaw 安全过滤器安装配置
"""

from setuptools import setup, find_packages

with open("README_STRUCTURED.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="openclaw-security",
    version="1.0.0",
    author="OpenClaw Security Team",
    author_email="security@openclaw.ai",
    description="数据安全分级防护系统，为OpenClaw输出端提供安全阀门",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Immortlll/MotoMap-security",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ],
        "ml": [
            "transformers>=4.20.0",
            "torch>=1.12.0",
        ],
        "cache": [
            "redis>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "openclaw-security-flask=openclaw_security.api.flask_server:main",
            "openclaw-security-fastapi=openclaw_security.api.fastapi_server:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
