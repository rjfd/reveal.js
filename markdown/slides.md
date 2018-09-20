## Ceph Messenger

<hr>
<p>Ricardo Dias | <a href="mailto:rdias@suse.com">rdias@suse.com</a></p>
<p>Techtalk 2018-09-21</p>

---

### Outline
<hr>

* <p>What is the Ceph messenger</p>
* <p>Messenger API</p>
* <p>Messenger Protocol Specification</p>
* <p>Messenger Implementation</p>
* <p>Messenger V2</p>

---

### What is the Ceph messenger?
<hr>

* <p>It's a wire-protocol specification;</p> <!-- .element: class="fragment" data-fragment-index="1" -->
* <p>and also, the corresponding software implementation</p> <!-- .element: class="fragment" data-fragment-index="2" -->

<div style="color: red; margin-top: 50px;"> <!-- .element: class="fragment" data-fragment-index="3" -->
<p>The messenger knows nothing about the Ceph distributed algorithms  and specific daemons protocols</p>
</div>

---

### Where can we find it?
<hr>

<img style="width: 90%; border: none; box-shadow: none;"
     src="images/ceph_daemons.png"> <!-- .element: class="fragment" data-fragment-index="1" -->

---

### Ceph Messenger
<hr>

<div style="font-size: 80%">
    <ul>
        <li style="margin-bottom: 20px;">Messenger is used as "small" communication library by the other Ceph libraries/daemons</li> <!-- .element: class="fragment" data-fragment-index="1" -->
        <li>It can be used as both server and client</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        <ul>
            <li>Ceph daemons (osd, mon, mgr, mds) act as both servers and clients</li> <!-- .element: class="fragment" data-fragment-index="2" -->
            <li style="margin-bottom: 20px;">Ceph clients (rbd, rgw) act as clients</li> <!-- .element: class="fragment" data-fragment-index="2" -->
        </ul>
        <li style="margin-bottom: 20px;">Abstracts the technology of the physical connection used between machines</li> <!-- .element: class="fragment" data-fragment-index="3" -->
        <li>Reliable delivery of messages with "exactly-once" semantics</li> <!-- .element: class="fragment" data-fragment-index="3" -->
    <ul>
</div>

---

### Ceph Messenger API
<hr>

<pre style="max-height: 550px; font-size: 0.4em;" class="cpp">
<code style="max-height: 510px;" data-trim data-noescape>
class Messenger {
    int start();
    int bind(const entity_addr_t& bind_addr);
    Connection *get_connection(const entity_inst_t& dest);

    // Dispatcher
    void add_dispatcher_head(Dispatcher *d);

    // server address
    entity_addr_t get_myaddr();
    int get_mytype();

    // Policy
    void set_default_policy(Policy p);
    void set_policy(int type, Policy p);
};

class Connection {
    bool is_connected();
    int send_message(Message *m);
    void send_keepalive();
    void mark_down();
    entity_addr_t get_peer_addr() const;
    int get_peer_type() const;
};
</code></pre>

--

### Ceph Messenger API
<hr>

<pre style="max-height: 500px; font-size: 0.4em;" class="cpp">
<code style="max-height: 500px;" data-trim data-noescape>
class Dispatcher {
    // Message handling
    bool ms_can_fast_dispatch(const Message *m) const;
    void ms_fast_dispatch(Message *m);
    bool ms_dispatch(Message *m);

    // Connection handling
    void ms_handle_connect(Connection *con);
    void ms_handle_fast_connect(Connection *con);
    void ms_handle_accept(Connection *con);
    void ms_handle_fast_accept(Connection *con);
    bool ms_handle_reset(Connection *con);
    void ms_handle_remote_reset(Connection *con);
    bool ms_handle_refused(Connection *con);

    // Authorization handling
    bool ms_get_authorizer(int dest_type, AuthAuthorizer **a, bool force_new);
    bool ms_verify_authorizer(Connection *con, int peer_type, int protocol,
				              ceph::bufferlist& authorizer,
                              ceph::bufferlist& authorizer_reply,
				              bool& isvalid, CryptoKey& session_key,
				              AuthAuthorizerChallenge *challenge);
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

### Messenger Wire-Protocol Specification
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
            <li>Banner + Identification Exchange</li> <!-- .element: class="fragment" data-fragment-index="3" -->
            <li>Session Establishment</li> <!-- .element: class="fragment" data-fragment-index="4" -->
            <ul>
                <li>Authentication</li> <!-- .element: class="fragment" data-fragment-index="4" -->
            </ul>
            <li>Message Exchange</li> <!-- .element: class="fragment" data-fragment-index="5" -->
        </ol>
    </ul>
</div>

--

### 1. Banner + Identification Exchange
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        arcgradient=20;
        c [label="connector"], a [label="accepter"];
        c -- a [label="connection established", linecolor="transparent", textcolor="grey"];

        c => a [label="c: banner\n", arcskip="1"],
        a => c [label="a: banner + addresses", arcskip="2"];
        |||;
        c => a [label="c: myaddress"];
        |||;
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.64em;">
<pre class="c"><code data-trim data-noescape>
struct ceph_entity_addr {  // 136 bytes
    __le32 type;
    __le32 nonce;  // unique id for process (e.g. pid)
    struct sockaddr_storage in_addr;
};

char *banner = "ceph v027";  // 9 bytes

struct addresses {  // 272 bytes
    ceph_entity_addr my_address;
    ceph_entity_addr peer_sock_address;
};

ceph_entity_addr myaddress;  // 136 bytes
</code></pre>
</div>

--

### 3. Session Establishment
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        arcgradient=20;
        c [label="connector"], a [label="accepter"];
        c -- a [label="banner + identification", linecolor="transparent", textcolor="grey"];

        c => a [label="c: connect", arcskip="1"];
        a => c [label="a: connect_reply", arcskip="1"];
        |||;
        c => a [label="c: connect", arcskip="1"];
        a => c [label="a: connect_reply", arcskip="1"];
        |||;

    }
    </pre>
</div>
<div class="right3" style="font-size: 0.64em;">
<pre class="c"><code data-trim data-noescape>
struct connect {  // 33 bytes
  __le64 features;     // supported feature bits
  __le32 host_type;    // CEPH_ENTITY\_TYPE_\*
  __le32 global_seq;   // count connections initiated by
                     // this host
  __le32 connect_seq;  // count connections initiated in
                     // this session
  __le32 protocol_version;
  __le32 authorizer_protocol;
  __le32 authorizer_len;
  __u8  flags;         // CEPH_MSG\_CONNECT_\*
};

struct connect_reply {  // 26 bytes
  __u8 tag;
  __le64 features;     // feature bits for this session
  __le32 global_seq;
  __le32 connect_seq;
  __le32 protocol_version;
  __le32 authorizer_len;
  __u8 flags;
}
</code></pre>
</div>

--

### 3. Session Establishment
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        arcgradient=20;
        c [label="connector"], a [label="accepter"];
        c -- a [label="banner + identification", linecolor="transparent", textcolor="grey"];

        c => a [label="c: connect", arcskip="1"];
        a => c [label="a: connect_reply", arcskip="1"];
        |||;
        c => a [label="c: connect", arcskip="1"];
        a => c [label="a: connect_reply", arcskip="1"];
        |||;

    }
    </pre>
</div>
<div class="right3" style="font-size: 0.62em;">
<pre class="c"><code data-trim data-noescape>
// TAGS
READY         1  // accepter->connector: ready for messages
RESETSESSION  2  // accepter->connector: reset, try again
WAIT          3  // accepter->connector: wait for racing
                 // incoming connection
RETRY_SESSION 4  // accepter->connector + cseq: try again
                 // with higher cseq
RETRY_GLOBAL  5  // accepter->connector + gseq: try again
                 // with higher gseq
BADPROTOVER   10 // bad protocol version
BADAUTHORIZER 11 // bad authorizer
FEATURES      12 // insufficient features
SEQ           13 // 64-bit int follows with seen
                 // seq number
CHALLENGE_AUTHORIZER 16  // ceph v2 doing accepter
                         // challenge

</code></pre>
</div>

--

### 3. Session Establishment - Authentication
<hr>

<div class="left2">
    <pre class="mscgen_js" style="box-shadow: none; width: 60%" >
    msc {
        arcgradient=20;
        c [label="connector"], a [label="accepter"];
        c -- a [label="banner + identification", linecolor="transparent", textcolor="grey"];

        c => a [label="c: connect + authbytes", arcskip="1"];
        a => c [label="a: connect_reply + authbytes", arcskip="1"];
        |||;
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.60em;">
<pre class="c"><code data-trim data-noescape>
struct connect {  // 33 bytes
  __le64 features;     // supported feature bits
  __le32 host_type;    // CEPH_ENTITY\_TYPE_\*
  __le32 global_seq;   // count connections initiated by
                     // this host
  __le32 connect_seq;  // count connections initiated in
                     // this session
  __le32 protocol_version;
  __le32 authorizer_protocol;
  __le32 authorizer_len;
  __u8  flags;         // CEPH_MSG\_CONNECT_\*
};

struct connect_reply {  // 26 bytes
  __u8 tag;
  __le64 features;     // feature bits for this session
  __le32 global_seq;
  __le32 connect_seq;
  __le32 protocol_version;
  __le32 authorizer_len;
  __u8 flags;
}
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
        c -- a [label="session establishment", linecolor="transparent", textcolor="grey"];

        c => a [label="c: message", arcskip="1"],
        a => c [label="a: message", arcskip="3"];
        c => a [label="c: message", arcskip="1"];
        |||;
        a => c [label="a: message + ack(2)", arcskip="1"];
        |||;
        c => a [label="c: message + ack(2)"];
    }
    </pre>
</div>
<div class="right3" style="font-size: 0.60em;">
<pre class="c"><code style="max-height: 500px;" data-trim data-noescape>
struct ceph_msg_header {
    __le64 seq;       // message seq# for this session
    __le64 tid;       // transaction id
    __le16 type;      // message type
    __le16 priority;  // priority.
    __le16 version;   // version of message encoding

    __le32 front_len; // bytes in main payload
    __le32 middle_len;// bytes in middle payload
    __le32 data_len;  // bytes of data payload
    __le16 data_off;  // sender: include full offset;
                    // receiver: mask against ~PAGE_MASK

    struct ceph_entity_name src;
}

struct message {
    __u8 tag;
    ceph_msg_header header;
    char payload[front_len + middle_len]
};

// TAGS
CLOSE          6  // closing pipe
MSG            7  // message
ACK            8  // message ack
KEEPALIVE      9  // just a keepalive byte!
KEEPALIVE2     14 // keepalive 2
KEEPALIVE2_ACK 15 // keepalive 2 reply

</code></pre>
</div>

---

### Messenger Implementation
<hr>

<ul>
    <li class="it">Source code location: `src/msg`</li> <!-- .element: class="fragment" data-fragment-index="1" -->
    <li>Two implementations</li> <!-- .element: class="fragment" data-fragment-index="2" -->
    <ul>
        <li>Simple messenger: `src/msg/simple`</li> <!-- .element: class="fragment" data-fragment-index="3" -->
        <li class="it">Asynchronous messenger: `src/msg/async`</li> <!-- .element: class="fragment" data-fragment-index="4" -->
    </ul>
    <li style="margin-top: 20px !important;">We will focus on the <span style="color: green;">`async` messenger</span></li> <!-- .element: class="fragment" data-fragment-index="5" -->
</ul>

--

### Async Messenger Implementation
<hr>

<img style="width: 90%; border: none; box-shadow: none;"
     src="images/messenger_components.png">

--

### Async Messenger Implementation
<hr style="margin-bottom: 1px;">

<pre style="max-height: 550px; font-size: 0.29em; box-shadow: none; margin-top: 0px;" class="text">
<code style="max-height: 610px; height: 610px;" data-trim data-noescape>
        send_server_banner                                             send_client_banner
                |                                                              |
                v                                                              V
        wait_client_banner                                              wait_server_banner
                |                                                              |
                |                                                              V
                V                                               handle_server_banner_and_identify
        wait_connect_message <-------------\                                   |
            |     |                        |                                   V
            |  wait_connect_message_auth   |                       send_connect_message <-----------\
            |     |                        |                                   |                    |
            V     V                        |                                   |                    |
    handle_connect_message_2               |                                   V                    |
            |              |               |                        wait_connect_reply              |
            V              V               |                          |        |                    |
         replace ---> send_connect_message_repl                       |        V                    |
            |                                                         |   wait_connect_reply_auth   |
            |                                                         |        |                    |
            V                                                         V        V                    |
          open ---\                                                 handle_connect_reply_2 ---------/
            |     |                                                            |
            |     V                                                            V
            |   wait_seq                                                  wait_ack_seq
            |     |                                                            |
            V     V                                                            V
        server_ready                                                      client_ready
                |                                                              |
                \-----------------------> wait_message <-----------------------/
                                         |  ^   |  ^
            /----------------------------/  |   |  |
            |                               |   |  \--------------------------------------------\
            V                    /----------/   V                                               |
    handle_keepalive2            |        handle_message_header                          read_message_footer
    handle_keepalive2_ack        |              |                                               ^
    handle_tag_ack               |              V                                               |
            |                    |        throttle_message                                      |
            \--------------------/              |                                               |
                                                V                                               |
                                        read_message_front --> read_message_middle --> read_message_data
</code></pre>

--

### Async Messenger Implementation
<hr>

<ul>
    <li class="it">Physical connection interface is non-blocking.</li>
    <li class="it">Fixed number of threads to process connections</li>
    <li class="it">The implementation ensures that only one physical connection is being used between two endpoints</li>
</ul>

---

# Messenger V2

--

### Messenger V2
<hr>

<ul>
    <li>The current protocol (aka V1) is not extensible</li> <!-- .element: class="fragment" data-fragment-index="1" -->
    <ul> <!-- .element: class="fragment" data-fragment-index="2" -->
        <li class="s it">Features, like encryption-on-the-wire, are not possible to implement without breaking the current protocol</li>
    </ul>
    <li>V2 protocol is a fully extensible protocol</li> <!-- .element: class="fragment" data-fragment-index="3" -->
    <ul> <!-- .element: class="fragment" data-fragment-index="4" -->
      <li class="s it">Decision on the features of the connection is done in the first step of the protocol</li>
    </ul>
    <li>Specification draft: http://docs.ceph.com/docs/master/dev/msgr2/</li> <!-- .element: class="fragment" data-fragment-index="5" -->
</ul>

--

### Messenger V2 - Protocol Phases
<hr>

<ol>
    <li>Banner Exchange</li>
    <li>Authentication Frame Exchange</li>
    <li>Message Flow Handshake Frame Exchange</li>
    <li>Message Frame Exchange</li>
</ol>

--

### Messenger V2 - Banner Exchange
<hr>

<pre class="c" style="font-size=0.4em;"><code style="max-height: 500px;" data-trim data-noescape>
struct banner {
    char prefix[5];  // "ceph "
    __le64 protocol_features_supported;
    __le64 protocol_features_required;
};
</code></pre>

<ul>
    <li>the behavior of the remaining protocol steps depends on the value of the features bitmasks</li> <!-- .element: class="fragment" data-fragment-index="1" -->
</ul>

--

### Messenger V2 - Frame
<hr>

<pre class="c" style="font-size=0.4em;"><code style="max-height: 500px;" data-trim data-noescape>
struct frame {
    __le32 frame_len;
    __le32 tag;
    char payload[/* frame_len - 4 - signature_size */];
    char signature[];
};
</code></pre>

--

### Messenger V2 - Authentication
<hr>

<ul>
    <li>More than one authentication method available</li> <!-- .element: class="fragment" data-fragment-index="1" -->
    <ul> <!-- .element: class="fragment" data-fragment-index="2" -->
        <li class="s it">Server announces the available methods, and Client chooses one of them</li>
    </ul>
    <div>  <!-- .element: class="fragment" data-fragment-index="3" -->
    <li class="it">Support for authentication methods that require more than 1 round trip</li>
    </div>
    <li>Signing and Encryption is decided by the Server after authentication is succeeded</li> <!-- .element: class="fragment" data-fragment-index="4" -->
</ul>

--

### Messenger V2 - Message Exchange and Handshaking
<hr>

<ul>
    <div>  <!-- .element: class="fragment" data-fragment-index="1" -->
    <li class="it">From this point, frames' payload may be encrypted or signed</li>
    </div>
    <div>  <!-- .element: class="fragment" data-fragment-index="2" -->
    <li class="it">Session state negotiation is very similar to the "Session Establishment" phase of the V1 protocol</li>
    </div>
</ul>

--

### Messenger V2 - Implementation
<hr>

<p>Work-in-progress: https://github.com/rjfd/ceph/tree/wip-msgr2</p>

---

# Q&A
