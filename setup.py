import setuptools

with open("README.rst", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="EncryptedBetterJSONStorage",
    version="1.0.0",
    author="Ankur Grover",
    author_email="ankur.grover@gmail.com",
    description="An optimized tinyDB storage extension",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/groverankur/EncryptedBetterJSONStorage",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Database",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    install_requires=["tinydb", "orjson", "blosc2", "mypy","cryptography"],
    python_requires=">=3.8",
    setup_requires=["isort"],
)
