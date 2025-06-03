This guide covers python version aliasing through .bashrc file. 

When to use: 
If you have multiple versions of python and need to configure shortcuts for each python version so that you can alias them in bash terminal. 

How: 

1. Create a file called ".bashrc" and place in your PC's root folder
2. in this file create an alias to reference the python version:

   alias python311='C:\\Users\\ABC123\\AppData\\Local\\Python\\Python311\\python.exe'

3. You can alias multiple versions
4. You can also use this method to create aliases that will be used in a bash terminal


Usage:

1. In the bash terminal you can call the alias to control the version of python you want to use:

   Example: Create a python311 environment using the alias reference

   python311 -m venv .venv

  
