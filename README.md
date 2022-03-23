# Encrypted File System

We suggest using a version of Python 3. Python 3.9 is recommended.

Make sure pip is up to date as well:

	 pip install --upgrade pip

If neither pip nor python are installed on your system already, please install them through the source of your choosing.

Create a virtual environment. Generally <environment_name> is venv We suggest doing this in the root of the project directory:

	python3 -m venv <environment_name>

Then activate the virtual environment using the following commands:

    macOS/Linux Ternimal
	    .  <environment_name>/bin/activate

    Windows Command Prompt/Bash Shell (Bash Shell is strongly recommended)
	    <environment_name>\Scripts\activate

If you've done this correctly, then (<environment_name>) should appear before the normal text that appears in the Terminal.

Use Pip3 to install the libraries in reqirements.txt with the <environment_name> activated in the Terminal:

    pip3 install <library_name>

In the same directory as manage.py and with the virtual environment running, run the UI as:

	python3 manage.py runserver

On the terminal, you will see a line along the lines of:

	Starting development server at http://127.0.0.1:8000/ 

Ctrl+Click on Windows or Command+Click on Mac to follow the link to the UI.
