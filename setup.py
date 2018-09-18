from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(name='lnkfile',
      version='0.2.1',
      description='Windows Shortcut file (LNK) parser',
      url='https://github.com/silascutler/LnkParse',
      author='Silas Cutler',
      author_email='silas.cutler@gmail.com',
      license='MIT',
      packages=['lnkfile'],
      zip_safe=False)
