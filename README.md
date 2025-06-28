# Veridian

Current Database has the following users:

1. test@now.in, 987654321, 50504e7a-ad2b-4230-beb4-fc9027591d75
2. user@testng.now, 12345678, 6088f10c-eff0-498d-93dd-f2071c9e0200

You can use them, or create new users. If you want to delete these users, simply delete the files in databases folder.

How to use:

	1. Create a virtual environment using python:
		a. Go to the directory you want to create the environment in.
		b. Open Powershell in the same directory
		c. Use the command python -m venv name
		d.Change directory to it
		e. After the virtual environment is created, execute the command .\Scripts\Activate
	3. You will now have started the virtual environment. Now, paste the requirements.txt file in the directory of virtual environment and use the command pip install -r requirements.txt
	4. After all the modules are downloaded. Copy the app.py, setup.bat and custom folder to the name directory.
	5. Run setup.bat as administrator
	6. Copy the databases, static and templates folder. Overwrite if they exist
	7. In powershell execute the command python app.py
	8. Ater this, click the port and your site will be running.
	
