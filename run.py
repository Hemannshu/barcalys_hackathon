import os
import subprocess
import sys
from threading import Thread
import time

def run_frontend():
    os.chdir('frontend')
    if sys.platform == 'win32':
        subprocess.run('npm start', shell=True)
    else:
        subprocess.run('npm start', shell=True)

def run_backend():
    os.chdir('backend')
    if sys.platform == 'win32':
        subprocess.run('python app.py', shell=True)
    else:
        subprocess.run('python3 app.py', shell=True)

if __name__ == '__main__':
    # Get the absolute path to the project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    # Start frontend and backend in separate threads
    frontend_thread = Thread(target=run_frontend)
    backend_thread = Thread(target=run_backend)

    frontend_thread.start()
    time.sleep(5)  # Wait for frontend to start
    backend_thread.start()

    # Wait for both threads to complete
    frontend_thread.join()
    backend_thread.join() 