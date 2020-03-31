import os
from oktapatientportal import app as application


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    application.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
