from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="moonito",
    version="2.1.0",
    author="Moonito",
    author_email="support@moonito.net",
    description="Real-time analytics and AI bot protection SDK for Python web applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/moonito-net/moonito-python",
    project_urls={
        "Bug Tracker": "https://github.com/moonito-net/moonito-python/issues",
        "Documentation": "https://moonito.net/docs",
        "Source Code": "https://github.com/moonito-net/moonito-python",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        # No external dependencies required - uses standard library
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
    keywords="ai blocking, ai bot blocker, traffic filtering, visitor filtering, bot detection, bot blocker, security, web protection",
)