## Ceph wire protocol revisited <br>Messenger V2

<hr>
<p>Ricardo Dias | <a href="mailto:rdias@suse.com">rdias@suse.com</a></p>
<p>FOSDEM'19 - Software Defined Storage devroom</p>

---

### Outline
<hr>

* <p>What is the Ceph messenger</p>
* <p>Messenger API</p>
* <p>Messenger V1 Limitations</p>
* <p>Messenger V2 Protocol</p>

---

### What is the Ceph messenger?
<hr>

* <p>It's a wire-protocol specification;</p> <!-- .element: class="fragment" data-fragment-index="1" -->
* <p>and also, the corresponding software implementation</p> <!-- .element: class="fragment" data-fragment-index="2" -->
* <p>Invisible to end-users</p> <!-- .element: class="fragment" data-fragment-index="3" -->
  * <p class="it">Unless when it's not working properly</p> <!-- .element: class="fragment" data-fragment-index="4" -->

<div style="color: red; margin-top: 50px;"> <!-- .element: class="fragment" data-fragment-index="5" -->
<p>The messenger knows nothing about the Ceph distributed algorithms  and specific daemons protocols</p>
</div>

---

### Where can we find it?
<hr>

<img style="width: 90%; border: none; box-shadow: none;"
     src="images/ceph_daemons.png"> <!-- .element: class="fragment" data-fragment-index="1" -->

---

### Ceph Messenger (1/2)
<hr>

<div style="font-size: 100%">
    <ul>
        <li style="margin-bottom: 20px;">Messenger is used as a "small" communication library by the other Ceph libraries/daemons</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        <li>It can be used as both server and client</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        <ul>
            <li>Ceph daemons (osd, mon, mgr, mds) act as both servers and clients</li> <!-- .element: class="fragment" data-fragment-index="2" -->
            <li style="margin-bottom: 20px;">Ceph clients (rbd, rgw) act as clients</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        </ul>
    <ul>
</div>

---

### Ceph Messenger (2/2)
<hr>

<div style="font-size: 100%">
    <ul>
        <li>Abstracts the technology of the physical connection used between machines</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        <ul>
            <li>Posix Sockets</li> <!-- .element: class="fragment" data-fragment-index="1" -->
            <li>RDMA</li> <!-- .element: class="fragment" data-fragment-index="1" -->
            <li>DPDK</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        </ul>
        <li style="margin-top: 20px;">Reliable delivery of messages with "exactly-once" semantics</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        <li style="margin-top: 20px;">Automatic handling of temporary connection failures</li> <!-- .element: class="fragment" data-fragment-index="3" -->
    <ul>
</div>

---

### Ceph Messenger API
<hr>

<pre style="max-height: 550px; font-size: 0.4em;" class="cpp">
<code style="max-height: 510px;" data-trim data-noescape>
class Messenger {
    <span>int start();</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>int bind(const entity_addr_t& bind_addr);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    Connection *get_connection(const entity_inst_t& dest);

    // Dispatcher
    void add_dispatcher_head(Dispatcher *d);

    <span>// server address</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>entity_addr_t get_myaddr();</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>int get_mytype();</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->

    <span>// Policy</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>void set_default_policy(Policy p);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>void set_policy(int type, Policy p);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
};

class Connection {
    <span>bool is_connected();</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    int send_message(Message *m);
    <span>void send_keepalive();</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    void mark_down();
    <span>entity_addr_t get_peer_addr() const;</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>int get_peer_type() const;</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
};
</code></pre>

--

### Ceph Messenger API
<hr>

<pre style="max-height: 550px; font-size: 0.5em;" class="cpp">
<code style="max-height: 550px;" data-trim data-noescape>
class Dispatcher {
    // Message handling
    <span>bool ms_can_fast_dispatch(const Message *m) const;</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>void ms_fast_dispatch(Message *m);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    bool ms_dispatch(Message *m);

    // Connection handling
    <span>void ms_handle_connect(Connection *con);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>void ms_handle_fast_connect(Connection *con);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    void ms_handle_accept(Connection *con);
    <span>void ms_handle_fast_accept(Connection *con);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>bool ms_handle_reset(Connection *con);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>void ms_handle_remote_reset(Connection *con);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->
    <span>bool ms_handle_refused(Connection *con);</span> <!-- .element: class="fragment fade-out" data-fragment-index="1" -->

    // Authorization handling
    bool ms_get_authorizer(int peer_type, AuthAuthorizer **a);
    bool ms_handle_authentication(Connection *con);
};
</code></pre>

--

### Ceph Messenger API
<hr>

<pre style="max-height: 500px; font-size: 0.4em;" class="cpp">
<code style="max-height: 500px;" data-trim data-noescape>
class Policy {
  // If true, the Connection is tossed out on errors.
  bool lossy;
  // If true, the underlying connection can't be re-established from this end.
  bool server;
  // If true, we will standby when idle
  bool standby;
  // If true, we will try to detect session resets
  bool resetcheck;

  // stateful server:     Policy(false, true, true, true)
  // stateless_server:    Policy(true, true, false, false)
  // lossless_peer:       Policy(false, false, true, false)
  // lossless_peer_reuse: Policy(false, false, true, true)
  // lossy_client:        Policy(true, false, false, false)
  // lossless_client:     Policy(false, false, false, true)
  }
};
</code></pre>

--

### Ceph Messenger API - Example
<hr>

<div class="left">
<pre style="max-height: 550px; font-size: 0.3em;" class="cpp">
<code style="max-height: 510px; width: 102%;" data-trim data-noescape>

class SimpleDispatcher : public Dispatcher {
    int received = 0;
    bool ms_dispatch(Message \*m) override {
        if (m->get_type() == MSG_PING) {
            Connection \*con = m->get_connection();
            con->send_message(new MPong());
        } else if (m->get_type() == MSG_PONG) {
            received++;
        }
    }
}

entity_addr_t bind_addr;
entity_addr_from_url(&bind_addr, "tcp://0.0.0.0:4321");

Messenger \*messenger;
messenger = Messenger::create(g_ceph_context,
                              "async+posix",
                              entity_name_t::MON(-1),
                              "simple_server", 0, 0);

messenger->set_default_policy(
    Messenger::Policy::stateless_server(0));

if ((r = messenger->bind(bind_addr))) {
    exit(r);
}

Dispatcher \*dispatcher = new SimpleDispatcher(messenger);
messenger->add_dispatcher_head(dispatcher);
messenger->start();
messenger->wait();

</code></pre>
</div>

<div class="right">
<pre style="max-height: 550px; font-size: 0.3em;" class="cpp">
<code style="max-height: 510px; width: 102%;" data-trim data-noescape>
Messenger \*messenger;
messenger = Messenger::create(g_ceph_context,
                              "async+posix",
                              entity_name_t::MON(-1),
                              "client", getpid(), 0);

messenger->set_default_policy(
    Messenger::Policy::lossy_client(0));

entity_inst_t dest;
dest.name = entity_name_t::MON(-1);
entity_addr_from_url(&dest.addr, "tcp://localhost:4321");

Dispatcher \*dispatcher = new SimpleDispatcher(messenger);
messenger->add_dispatcher_head(dispatcher);

if ((r = messenger->start())) {
    exit(r);
}

Connection *conn;
conn = messenger->get_connection(dest);

for (int i = 0; i < 1000; ++i) {
    // asynchronous call
    conn->send_message(new MPing());
}

while (dispatcher->received < 1000) {
    // sleep a bit
}
</code></pre>
</div>

---

### Messenger V1 Wire Protocol
<hr>

<div style="font-size: 100%">
    <ul>
        <li style="margin-bottom: 20px;">The first wire-protocol of Ceph</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        <li style="margin-bottom: 20px;">No extensability at an early stage of the protocol</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        <li style="margin-bottom: 20px;">No data authenticity supported</li> <!-- .element: class="fragment" data-fragment-index="3" -->
        <li style="margin-bottom: 20px;">No data encryption supported</li> <!-- .element: class="fragment" data-fragment-index="4" -->
        <li style="margin-bottom: 20px;">Limited support for different authentication protocols</li> <!-- .element: class="fragment" data-fragment-index="5" -->
        <li style="margin-bottom: 20px;">No strict structure for protocol internal messages</li> <!-- .element: class="fragment" data-fragment-index="6" -->
  <!--  <li>Code maintainability problems</li>
        <ul>
            <li>Old code with many iterations from the original</li>
            <li>Protocol code mixed with connection handling code</li>
        </ul> -->
    <ul>
</div>

---

### Messenger V2 Wire Protocol (1/2)
<hr>

<div style="font-size: 100%">
    <ul>
        <li>By default is available on the IANA port 3300 in Ceph Monitors</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        <ul>
            <li>Messenger V1 will still be available through port 6789</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        </ul>
        <li style="margin-top: 20px;">Only Ceph Nautilus userspace libraries support V2</li> <!-- .element: class="fragment" data-fragment-index="3" -->
        <ul>
            <li>Ceph kernel modules still talk V1</li> <!-- .element: class="fragment" data-fragment-index="3" -->
        </ul>
        <li style="margin-top: 20px;">Still in development as Nautilus has not been released yet</li> <!-- .element: class="fragment" data-fragment-index="4" -->
    </ul>
</div>

---

### Messenger V2 Wire Protocol (2/2)
<hr>

<div style="font-size: 100%">
    <ul>
        <li style="margin-top: 20px;">Complete redesign and implementation</li> <!-- .element: class="fragment" data-fragment-index="5" -->
        <li style="margin-top: 20px;">Extensible protocol</li> <!-- .element: class="fragment" data-fragment-index="6" -->
        <ul>
            <li>A different path can be taken in a very early stage of the protocol</li> <!-- .element: class="fragment" data-fragment-index="6" -->
        </ul>
        <li style="margin-top: 20px;">No limitations on the authentication protocols used</li> <!-- .element: class="fragment" data-fragment-index="7" -->
        <li style="margin-top: 20px;">Encryption-on-the-wire support</li> <!-- .element: class="fragment" data-fragment-index="8" -->
        <!-- <li style="margin-top: 20px;">Specification draft: http://docs.ceph.com/docs/master/dev/msgr2/</li> -->
    </ul>
</div>

---

### Messenger V2 Specification
<hr>

<div class="left" style="width: 40%">
    <ul>
        <li>Actors:</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        <ul>
            <li>Connector</li> <!-- .element: class="fragment" data-fragment-index="1" -->
            <li>Accepter</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        </ul>
    <ul>
</div>

<div class="right" style="width: 60%">
    <ul>
        <li>Phases</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        <ol>
            <li>Banner Exchange</li> <!-- .element: class="fragment" data-fragment-index="3" -->
            <li>Authentication</li> <!-- .element: class="fragment" data-fragment-index="4" -->
            <li>Session Handshake</li> <!-- .element: class="fragment" data-fragment-index="4" -->
            <li>Message Exchange</li> <!-- .element: class="fragment" data-fragment-index="5" -->
        </ol>
    </ul>
</div>

--

### Message Frame
<hr>

<pre class="cpp" style="font-size=0.35em;"><code style="max-height: 500px;" data-trim data-noescape>
struct frame {
    uint32_t frame_len;           // 4 bytes
    uint32_t tag;                 // 4 byts
    char payload[frame_len - 4];
};


struct encrypted_frame {
    uint32_t frame_len;
    uint32_t tag;
    char encrypted_payload[frame_len - 4];
};
</code></pre>

--

### 1. Banner Exchange
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        arcgradient=20;
        c [label="connector"], a [label="accepter"];
        c -- a [label="connection established", linecolor="transparent", textcolor="grey"];

        c => a [label="banner", arcskip="1"],
        a => c [label="banner", arcskip="2"];
        |||;
        |||;
        --- [label="We can change the \nbehavior of the protocol at\n this point based on the\n supported/required features", linecolor="grey", textbgcolor="white", textcolor="darkgreen"];
        a => c [label="hello", arcskip="2"];
        c => a [label="hello", arcskip="1"];
        
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.70em;">
<pre class="c"><code data-trim data-noescape>
struct banner_payload {
    uint64_t supported_features;
    uint64_t required_features;
    entity_addr_t peer_address;
}

struct banner {
    char banner[8]; // "ceph v2\n"
    uint64_t payload_len; 
    struct banner_payload pyload;
};

struct hello {
    uint8_t entity_type;
    entity_addr_t peer_address;
}
</code></pre>
</div>

--

### 2. Authentication
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        c [label="connector"], a [label="accepter"];
        c => a [label="auth_request"];
        a => c [label="auth_bad_method", linecolor="red", textcolor="red"];
        c => a [label="auth_request"];
        |||;
        a => c [label="auth_reply_more"];
        c => a [label="auth_request_more"];
        --- [label=" several rounds ", textcolor="grey", linecolor="grey"];
        a => c [label="auth_done"];
        --- [label="From this point message \nframes can be encrypted", textcolor="grey", linecolor="transparent"];
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.7em;">
<pre style="max-height: 550px;" class="c"><code style="max-height: 550px;" data-trim data-noescape>
struct auth_request {
    uint32_t method;
    uint32_t preferred_modes[num_modes];
    char auth_payload[payload_len];
}

struct auth_bad_method {
    uint32_t method;
    int result;
    uint32_t allowed_methods[num_methods]; 
    uint32_t allowed_modes[num_modes]; 
};

struct auth_reply_more {
    char auth_payload[payload_len];
};

struct auth_request_more {
    char auth_payload[payload_len];
};

struct auth_done {
    uint64_t global_id;
    uint32_t mode;
    char auth_payload[payload_len];
};
</code></pre>
</div>

--

### 3. Session Handshake (new session)
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        wordwraparcs=on;
        c [label="connector"], a [label="accepter"];
        c => a [label="client_ident"];
        a => c [label="server_ident"];
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.7em;">
<pre style="max-height: 550px;" class="c"><code style="max-height: 550px;" data-trim data-noescape>
struct client_ident {
    entity_addrvec_t addrs;
    int64_t global_id;
    uint64_t global_seq;
    uint64_t supported_features;
    uint64_t required_features;
    uint64_t flags;
};

struct server_ident {
    entity_addrvec_t addrs;
    int64_t global_id;
    uint64_t global_seq;
    uint64_t supported_features;
    uint64_t required_features;
    uint64_t flags;
    uint64_t cookie;
};

</code></pre>
</div>

--

### 3. Session Handshake (reconnect)
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        wordwraparcs=on;
        c [label="connector"], a [label="accepter"];
        c => a [label="reconnect"];
        a => c [label="reconnect_ok"];
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.7em;">
<pre style="max-height: 550px;" class="c"><code style="max-height: 550px;" data-trim data-noescape>
struct reconnect {
    entity_addrvec_t addrs;
    uint64_t cookie;
    uint64_t global_seq;
    uint64_t connect_seq;
    uint64_t msg_seq;
};

struct reconnect_ok {
    uint64_t msg_seq;
};

</code></pre>
</div>

--

### 4. Message Exchange
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        arcgradient=20;
        c [label="connector"], a [label="accepter"];
        --- [label="session establishment", linecolor="gray", textcolor="grey"];

        c => a [label="message", arcskip="1"],
        a => c [label="message", arcskip="3"];
        c => a [label="message", arcskip="1"];
        |||;
        a => c [label="message + ack(2)", arcskip="1"];
        |||;
        c => a [label="message + ack(2)"];
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.60em;">
<pre class="c"><code style="max-height: 500px;" data-trim data-noescape>
struct message {
    __u8 tag;
    ceph_msg_header2 header;  // includes last seen msg seq
    char payload[front_len + middle_len]
};

// TAGS
CLOSE          6  // closing pipe
MSG            7  // message
ACK            8  // message ack
KEEPALIVE2     14 // keepalive 2
KEEPALIVE2_ACK 15 // keepalive 2 reply

</code></pre>
</div>

---

### Frame Integrity, Auhtenticity, and Confidentiality
<hr>

<ul>
    <li class="it">Integrity:</li> <!-- .element: class="fragment" data-fragment-index="1" -->
    <ul>
        <li>CRC in frame header (length + tag)</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        <li>CRC in messages payload (same as in V1)</li> <!-- .element: class="fragment" data-fragment-index="3" -->
    </ul>
    <li class="it" style="margin-top: 30px;">Authenticity and Confidentiality:</li> <!-- .element: class="fragment" data-fragment-index="4" -->
    <ul>
        <li>Frame payload only</li> <!-- .element: class="fragment" data-fragment-index="5" -->
        <li>Authenticity with SHA256 HMAC</li> <!-- .element: class="fragment" data-fragment-index="6" -->
        <li>Confidentiality with AES encryption</li> <!-- .element: class="fragment" data-fragment-index="7" -->
    </ul>
</ul>

---

### Messenger Implementation
<hr>

<ul>
    <li class="it">Source code location: `src/msg`</li> <!-- .element: class="fragment" data-fragment-index="1" -->
    <li style="margin-top: 20px !important;">Two implementations</li> <!-- .element: class="fragment" data-fragment-index="2" -->
    <ul>
        <li>Simple messenger: `src/msg/simple`</li> <!-- .element: class="fragment" data-fragment-index="3" -->
        <li class="it">Asynchronous messenger: `src/msg/async`</li> <!-- .element: class="fragment" data-fragment-index="4" -->
    </ul>
    <li style="margin-top: 20px !important;">V2 Protocol only available in async messenger</li> <!-- .element: class="fragment" data-fragment-index="5" -->
</ul>

---

# Q&A
