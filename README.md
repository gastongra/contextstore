# contextstore
Simple demo client for avaya breeze context store rest snap-in

Demonstrates how ContextStoreRest snap-in works by  creating 10 contexts with different lease times and showing them in the console and in a web UI.

The web UI runs in a dedicated thread - contextServer - spawn from the main process and can be accessed by  pointing your web browser to http://127.0.0.1:8001.

CSSimpleClient also spawns a second  thread named ContextsManager. It´s purpose is to retrieve contexts from the ContextStoreRest snap-in and save them to a local dictionary. This dictionary is what contextServer shows in the web UI.

Context Store Simple Client has been tested with Python 3.4 and ContextStoreRest snap-in release 3.4

## Configuration
- Set hostname, port, initial lease time and logging level variables in the main function
- When instantiating CSSSimpleClient you can set "web" named parameter to True or False, depending on whether you want the Web UI to be started or not. 
- The Root CA´s certificate for the CA issuing the breeze cluster identity certificate - tipically System Manager´s CA - has to be stored in a file named cacerts.pem

## Usage
        python csSimpleClient.py
