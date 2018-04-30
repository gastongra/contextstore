#!/usr/bin/env python
# Gaston Graces
# May 2018

import os
import sys
from time import sleep
from threading import Thread
import requests
import logging
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client


class StoppableHTTPServer (HTTPServer):
    def serve_forever(self):
        """Handle one request at a time until stopped."""
        self.stop = False
        while not self.stop:
            self.handle_request()


class ContextsHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Send response status code:
        self.send_response(200)
        # Send headers:
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        # Send HTML content:
        page = """
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="1" />
        <title>Contexts Server</title>
        </head>
        <body>
        <h1>Contexts Created:</h1>
        """
        for key, value in sorted(contexts.items()):
            context = "<p>ContextId: "+str(key)+" "+str(value)+"</p>"
            page = page + context
        page = page + """
        </body>
        </html>
        """
        self.wfile.write(bytes(page, "utf8"))
        return

    def do_QUIT(self):
        """send 200 OK response, and set server.stop to True"""
        self.send_response(200)
        self.end_headers()
        self.server.stop = True

    def log_message(self, format, *args):
        return


class CSSimpleClient(object):
    def __init__(self, hostname, port, web=False):
        self.__allDone__ = False
        self.__webInterface__ = False
        self.__contextServer__ = None
        self.__contextsManager__ = None
        self.__csSession__ = requests.Session()
        cacertsFile = os.getcwd()+"\cacerts.pem"
        self.__csSession__.verify = cacertsFile
        self.__csSession__.headers = {'content-type': 'application/json'}
        self.__contextsManager__ = Thread(target=self.contextsManager, args = (hostname, port))
        self.__contextsManager__.setName("contextsManager")
        self.__contextsManager__.start()
        if web:
            self.__contextServer__ = Thread(target=self.contextServer)
            self.__contextServer__.setName("contextServer")
            self.__contextServer__.start()
            self.__webInterface__ = True

    def contextServer(self):
        # HTTP server to show contexts dictionary in a web browser
        logging.info("contextServer starting on http://127.0.0.1:8001")
        server_address = ('127.0.0.1', 8001)
        httpd = StoppableHTTPServer(server_address, ContextsHTTPRequestHandler)
        httpd.serve_forever()  # serves http requests until stopped by client
        logging.info("Received QUIT message. Goodbye!")

    def contextsManager(self, hostname, port):
        # This thread gets contexts from the Context Store breeze cluster and
        # updates contexts dictionary accordingly
        global contexts
        logging.info("contextsManager started. Updating contexts dictionary "
                     "until allDone is set to True.")
        while not self.__allDone__:
            contexts2 = {k:self.getContextInfo(k, hostname, port) for k in list(contexts)}
            for k in contexts2:
                contexts[k] = contexts2[k]
        logging.info("All Done is True. Nos vamos!!!")

    def getContextInfo(self, contextId, hostname, port):
        contextInfo = "Unknown"
        url = self.getGetContextMessage(hostname, port, contextId)
        response = self.sendGet(url)
        if response is not None:
            lease = contexts[contextId][0]
            contextInfo = [lease, response.text]
        else:
            logging.error("Received None response from sendGet. "
                          "Skipping context ...")
        return(contextInfo)

    def getSession(self):
        return self.__csSession__

    def getCreateContextMessage(self, ip, port, LeaseTime):
        message = ("https://"+ip+":"+str(port)+"/services/ContextStoreRest/cs/"
                   "contexts/?lease="+str(LeaseTime)+"&sid=Not%20Specified&rid"
                   "=0&rules=false&shortid=false")
        return(message)

    def getGetContextMessage(self, ip, port, contextId):
        message = ("https://"+ip+":"+str(port)+"/services/ContextStoreRest/cs/"
                   "contexts/"+str(contextId))
        return(message)

    def sendPost(self, url, payload):
        response = None
        try:
            response = self.__csSession__.post(url, json=payload)
        except requests.exceptions.Timeout:
            logging.error("Timeout when trying to connect to Context Store"
                          ". Check Breeze cluster availability.")
        except requests.exceptions.TooManyRedirects:
            logging.error("TooManyRedirects exception when trying to "
                          "connect to Context Store. Check Breeze cluster "
                          "availability.")
        except requests.exceptions.ConnectionError:
            logging.error("sendPost Connection to Context Store failed. "
                          "Check Breeze cluster availability.")
        except requests.exceptions.RequestException as e:
            logging.error(str(e) + " exception when trying to connect to "
                                   "ContextStore. Dying ...")
        return(response)

    def sendGet(self, url):
        response = None
        try:
            response = self.__csSession__.get(url)
        except requests.exceptions.Timeout:
            logging.error("Timeout when trying to connect to Context Store."
                          " Check Breeze cluster availability.")
        except requests.exceptions.TooManyRedirects:
            logging.error("TooManyRedirects exception when trying to "
                          "connect to Context Store. Check Breeze cluster "
                          "availability.")
        except requests.exceptions.ConnectionError:
            logging.error("sendGet Connection to Context Store failed. "
                          "Check Breeze cluster availability.")
        except requests.exceptions.RequestException as e:
            logging.error(str(e) + " exception when trying to connect to "
                                   "ContextStore. Dying ...")
        return(response)

    def setAlldone(self):
        self.__allDone__ = True

    def doGracefulShutdown(self):
        logging.info("closing requests session ...")
        self.__csSession__.close()
        if self.__webInterface__:
            logging.info("Shutting down Contexts HTTP server ...")
            # send QUIT request to http server
            conn = http.client.HTTPConnection("localhost:8001")
            conn.request("QUIT", "/")
            conn.getresponse()
            self.__webInterface__ = False
        logging.info("Setting allDone to True ...")
        self.__allDone__ = True


def main():
    '''
    Requests API:
    http://docs.python-requests.org/en/master/user/advanced/
    '''
    requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
    global contexts
    hostname = "mycscluster.example.com"  # Breeze Cluster FQDN
    port = 443  # Secure CSRest service port
    lease = 10  # Initial lease time for creating contexts
    '''
    Set logging level as needed:
    Level	Numeric value
    CRITICAL	50
    ERROR		40
    WARNING		30
    INFO		20
    DEBUG		10
    NOTSET		0
    '''
    logLevel = logging.INFO
    logging.basicConfig(level=logLevel, format='%(relativeCreated)6d|'
                                               '%(threadName)15s|'
                                               '%(levelname)s|%(message)s')
    logging.info("Initializing Values(Hostname,Port,Lease):"+hostname+"|" +
                 str(port)+"|"+str(lease))
    logging.info("Creating CSSimpleClient instance")
    csCli = CSSimpleClient(hostname, port, web=True)
    response = None
    for i in range(1, 11):
        lease += 2
        url = csCli.getCreateContextMessage(hostname, port, lease)
        payload = {"contextId":i,"data":{"Nombre":"Gaston",
        "CustId":"12345678","Auto":"Verde","campo":"cualquiera"}}
        logging.info("Sending CreateContext Msg with payload "+str(payload))
        logging.debug(url)
        response = csCli.sendPost(url, payload)
        if response is None:
            logging.critical("Couldnt create context. Initiating graceful "
                             "shutdown now")
            csCli.doGracefulShutdown()
            sys.exit(1)
        logging.info("Response: " + str(response.status_code) + " - " +
                     response.text)
        contexts[i] = [lease, "Not Retrieved Yet"]
    input("Press Enter to end the program ...")
    csCli.doGracefulShutdown()
    sleep(2)
    logging.info('Graceful shutdown completed. Ending program ...')


if __name__ == '__main__':
    contexts = {}
    main()
