from setuptools import setup, find_packages

setup(
    name="netshield",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "torch",
        "numpy",
    ],
    description="NetShield - AI-powered cybersecurity module for threat detection.",
    author="Your Name",
    author_email="your_email@example.com",
    url="https://github.com/yourusername/netshield",
    license="MIT",
)
