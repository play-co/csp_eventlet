from __future__ import with_statement
import eventlet
from eventlet import wsgi
import cgi
import uuid
import base64
try:
    import json
except:
    import simplejson as json
    
    
def test():
    try:
        l = csp_listener(("", 8000))
        while True:
            conn, addr = l.accept()
            print 'ACCEPTED', conn, addr
            eventlet.spawn(echo, conn)
    except KeyboardInterrupt:
        print "Ctr-c, Quitting"
        
def echo(conn):
    conn.send("Welcome")
    while True:
        d = conn.recv(1024)
        print 'RECV', d
        if not d:
            break
        conn.send(d)
        print 'SEND', d
    print "Conn closed"

def csp_listener((interface, port)):
    l = Listener(interface, port)
    l.listen()
    return l

class Listener(object):
    def __init__(self, interface=None, port=None):
        self.interface = interface
        self.port = port
        self._accept_channel = eventlet.queue.Queue(0)
        self._sessions = {}
        
    def listen(self):
        eventlet.spawn(wsgi.server, eventlet.tcp_listener((self.interface, self.port)), self)

    def __call__(self, environ, start_response):
        path = environ['PATH_INFO']
        handler = getattr(self, 'render_' + path[1:], None)
        if not handler:
            start_response('404 Not Found', [('Access-Control-Allow-Origin','*')])
            return ""
        try:
            form = environ['csp.form'] = get_form(environ)
        except Exception, e:
#            raise
            start_response('500 internal server error', [('Access-Control-Allow-Origin','*')])
            return "Error parsing form"
        session = None
#        print '**', path, form
        if path != "/handshake":
#            print 'a'
            key = form.get("s", None)
            if key not in self._sessions:
                # TODO: error?
                
                start_response('404 Session not found', [('Access-Control-Allow-Origin','*')])
                return "'Session not found'"
#            print 'b'
            session = self._sessions[key]
#            print 'c'
            session.update_vars(form)
#            print 'd'
#        print 'e'
        x = handler(session, environ, start_response)
#        print 'f, x is', x
        if not x:
#            print "ERROR", path
            return ".."
        return x

    def render_comet(self, session, environ, start_response):
        return session.comet_request(environ, start_response)

    def render_handshake(self, session, environ, start_response):
        key = str(uuid.uuid4()).replace('-', '')
        session = CSPSession(self, key, environ)
        self._sessions[key] = session
        eventlet.spawn(self._accept_channel.put, (session._socket, ("", 0)))
        return session.render_request({"session":key}, start_response)

    def render_close(self, session, environ, start_response):
        session.close()
        return session.render_request("OK", start_response)

    def render_send(self, session, environ, start_response):
#        print 'render_send'
        session.read(environ['csp.form'].get('d', ''))
        return session.render_request("OK", start_response)

    def render_reflect(self, session, environ, start_response):
        return environ['csp.form'].get('d', '')
    
    def accept(self):
        return self._accept_channel.get()
    
    def _teardown(self, session):
        del self._sessions[session.key]
    
def get_form(environ):
    form = {}
    qs = environ['QUERY_STRING']
    for key, val in cgi.parse_qs(qs).items():
        form[key] = val[0]
    if environ['REQUEST_METHOD'].upper() == 'POST':
        data = environ['wsgi.input'].read()
#        print 'GOT out of FORM', repr(data)
        form['d'] = data
    return form
        
        
class CSPSocket(object):
    def __init__(self, session):
        self.session = session
                
    def send(self, data):
        return self.session.blocking_send(data)
    
    def recv(self, max):
        return self.session.blocking_recv(max)
        
class CSPSession(object):
    
    def __init__(self, parent, key, environ):
        self._recv_event = None
        self.parent = parent
        self.key = key
        self.packets = []
        self.send_id = 0
        self.buffer = ""
        self._read_queue = eventlet.queue.Queue()
        self.is_closed = False
        self.last_received = 0
        self._comet_request_lock = eventlet.semaphore.Semaphore(1)
        self._comet_request_channel = eventlet.queue.Queue(0)
        self._activity_queue = eventlet.queue.Queue()
        self._raise_exc_next_recv = False
        
        self._received_null_packet = False
        self._sent_null_packet = False
        
        self.conn_vars = {
            "rp":"",
            "rs":"",
            "du":30,
            "is":0, # False
            "i":0,
            "ps":0,
            "p":"",
            "bp":"",
            "bs":"",
            "g":0, # False
            "se":0, # False
            "ct":"text/html"
        }
        self.prebuffer = ""
        self.update_vars(environ['csp.form'])
        self._socket = CSPSocket(self)
        eventlet.spawn(self._timeout, False)


    def _timeout(self, is_teardown):
#        print 'start _timeout'
        while True:
            # SPEC TODO: No mention in csp spec (Draft 0.4 Nov 19, 2009) of
            #            session timeout. Choosing twice the comet duration or
            #            60 seconds when du = 0 (polling mode)
            with eventlet.timeout.Timeout(self.conn_vars['du'] * 2 or 60, False):
#                print 'timeout?'
                if self._activity_queue.get():
#                    print 'timeout ended gracefully'
                    break
#                print 'not yet.'
                continue
            if is_teardown:
#                print 'teardown timeout called...'
                self.teardown()
            else:
#                print 'close due to timeout...'
                self.close()
            break
    
    def blocking_send(self, data):
        if self.is_closed:
            raise Exception("CSPSession is closed, cannot call send")
        if isinstance(data, unicode):
            # NOTE: we specifically don't encode the data. You can only send 
            #       bytes over csp. Do you rown decoding before you call send.
            data = str(data)
        self.send_id+=1
        self.packets.append([self.send_id, 1, base64.urlsafe_b64encode(data)])
        if self._has_comet_request():
            self._comet_request_channel.put(None)
        return len(data)
    
    def blocking_recv(self, max):
        if not self.buffer:
            if self.is_closed:
                if not self._raise_exc_next_recv:
#                    print 'returning empty data'
                    self._raise_exc_next_recv = True
                    return ""
                else:
                    raise Exception("CSPSession is closed, cannot call recv")
            self._read_queue.get()
#        print 'self.buffer', repr(self.buffer)
        data = self.buffer[:max]
        self.buffer = self.buffer[max:]
        if not data:
#            print 'returning empty data'
            self._raise_exc_next_recv = True
        return data


    def read(self, rawdata):
        # parse packets, throw out duplicates, forward to protocol
        packets = json.loads(rawdata)
        for key, encoding, data in packets:
            if data == None:
                self._null_received()
                break
            # TODO: This is pretty ridiculous... I'm sure we can just tell 
            #       json.loads to just leave this as raw/ascii/binary somehow.
            if isinstance(data, unicode):
                data = data.encode('utf-8', 'replace')
            if self.last_received >= key:
                continue
            if encoding == 1:
                data = base64.urlsafe_b64decode(data + '==' )
            self.last_received = key
            self.buffer += data
            if data:
                self._read_queue.put(None)

    def update_vars(self, form):
#        print 'top of update vars'
        self._activity_queue.put(None)
        for key in self.conn_vars:
            if key in form:
                newVal = form[key]
                varType = self.conn_vars[key].__class__
                try:
                    typedVal = varType(newVal)
                    if key == "g" and self._has_comet_request() and self.conn_vars["g"] != typedVal:
                        self.end_stream()
                    self.conn_vars[key] = typedVal
                    if key == "ps":
                        self.prebuffer = " "*typedVal
                except:
                    pass
        ack = form.get("a","-1")
        try:
            ack = int(ack)
        except ValueError:
            ack = -1
        while self.packets and ack >= self.packets[0][0]:
            self.packets.pop(0)
#        print 'update_vars', self.is_closed, self.packets
#        if self.is_closed and not self.packets:
#            print 'call teardown'
#            self.teardown()

    def close(self):
        self.is_closed = True
        self.send_id+=1
        self.packets.append([self.send_id, 0, None])
#        print 'appending null packet..'
        if self._has_comet_request():
            self._comet_request_channel.put(None)
        if self._activity_queue.getting():
            self._activity_queue.put(True)
        eventlet.spawn(self._timeout, True)
            
    def teardown(self):
        self._read_queue.put(None)
        if self._activity_queue.getting():
            self._activity_queue.put(True)
        if self._has_comet_request():
            self._comet_request_channel.put(None)
        self.parent._teardown(self)
        
    def _null_sent(self):
        self._sent_null_packet = True
        if self._sent_null_packet and self._received_null_packet:
            self.teardown()
        
    def _null_received(self):
        self._received_null_packet = True
        if self._sent_null_packet and self._received_null_packet:
            self.teardown()
        else:
            self.close()
        
        
    def _has_comet_request(self):
        return bool(self._comet_request_channel.getting())
    
    def comet_request(self, environ, start_response):
        if not self.packets:
            self._comet_request_lock.acquire()
            if self._has_comet_request():
                self._comet_request_channel.put(None)
            self._comet_request_lock.release()
            duration = self.conn_vars['du']
            if duration:
                with eventlet.timeout.Timeout(duration, False):
                    self._comet_request_channel.get()

        headers = [ ('Content-type', self.conn_vars['ct']) ,
                    ('Access-Control-Allow-Origin','*') ]
        start_response("200 Ok", headers)
        
        output = self.render_prebuffer() + self.render_packets(self.packets)
#        print 'comet returning', output
        if self.packets and self.packets[-1][2] is None:
            self._null_sent()
        return output
            
            
    def render_prebuffer(self):
        return "%s%s"%(self.prebuffer, self.conn_vars["p"])

    def render_packets(self, packets):
        if self.conn_vars['se']:
            sseid = "\r\n"
        else:
            sseid = ""
        if self.conn_vars["se"] and packets:
            sseid = "id: %s\r\n\r\n"%(packets[-1][0],)
        return "%s(%s)%s%s" % (self.conn_vars["bp"], json.dumps(packets), self.conn_vars["bs"], sseid)            

            
#    session.render_request({"session":key}, start_response)
    def render_request(self, data, start_response):
        headers = [ ('Content-type', self.conn_vars['ct']),
                    ('Access-Control-Allow-Origin','*') ]
        start_response("200 Ok", headers)
        output = "%s(%s)%s" % (self.conn_vars["rp"], json.dumps(data), self.conn_vars["rs"])
        return output
    
if __name__ == "__main__": 
    test()
