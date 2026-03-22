from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ez-appsec",
    version="0.1.0",
    author="John Felten",
    author_email="jfelten.work@gmail.com",
    description="AI-powered application security scanning - free replacement for GitLab and GitHub security scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jfelten/ez-appsec",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Security",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "openai>=1.0",
        "pydantic>=2.0",
        "pyyaml>=6.0",
        "requests>=2.28",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ez-appsec=ez_appsec.cli:main",
        ],
    },
)
