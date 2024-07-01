---
title: "Intro to Keyrings"
date: 2023-10-12
tags:
  - linux
  - security
  - applications
  - keyrings
categories:
  - security
  - linux
  - keyrings
---

This is the third part of the series on securing applications on Linux. The first part was about Linux Seccompand the second part was about Linux Landlock. This third part is about Linux Keyrings.

## What are Linux Keyrings?

As usual we start citing the appropriate man page, [keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html):

```
The Linux key-management facility is primarily a way for various
kernel components to retain or cache security data,
authentication keys, encryption keys, and other data in the
kernel
System call interfaces are provided so that user-space programs
can manage those objects and also use the facility for their own
purposes; see add_key(2), request_key(2), and keyctl(2).
```

So, this means that we can use the kernel as a vault, storing secrets in it. There are various types of keys we can create:

* keyrings – are special keys to which other keys or keyrings can be linked to, they work almost as a directory, their purpose is to keep alive keys so that those keys are not garbage collected by the kernel

* user – are keys which maximum size is 32,767 bytes, they are used to store user specific data and are managed by user
space applications

* logon – similar to user keys except that cannot be read from user space, those are useful to store credentials such as user and password

* big_key – similar to user except that they can be up to 1MiB in size, these kind of keys could may be stored on tmpfs

We mentioned before that if a key is not anchored to a keyring it will be garbage collected by the kernel, so the kernel offers a way to keep keys alive, this is done by linking keys to a keyring. Notice that keyrings themselves can be garbage collected, so in turn also keyrings need to be anchored to another keyring. To solve this problem the kernel makes available some keyrings which sole purpose is to be used as anchors, these keyrings are:

* Process keyrings – we’ll look at them in a moment, since are the ones we’ll use in this article
  * process-keyring(7)
  * thread-keyring(7)
  * session-keyring(7)

* User keyrings – these are per UID keyrings and are shared with all the processes spawned by the same UID
  * user-keyring(7)
  * user-session-keyring(7)

* Persistence keyrings – these are keyrings which can persist across user sessions, so that programs that need to use    credentials to perform operations can get them without the need of a user session
  * persistent-keyring(7)

* Special keyrings – thes are keyrings that holds system wide keys, such as the ones used for the kernel modules signature verification

Notice that the one above is a short description and the reader is encouraged to check appropriate man pages to have a deeper understanding of the topic.

## Process Keyrings

These keyrings exist as anchoring keyring in order to be used by processes and threads. Their existence is directly bound to the process existence, so as long as the process is alive it will be possible to access the keyring. There are three types of process keyrings:

* process-keyring(7) – it is created when a process accesses it for the first time, and it is accessible by all the threads of the process, notice however that on execve(2) the keyring it is destroyed, and this makes perfectly sense as this syscall replaces entirely the process memory image

* thread-keyring(7) – it is created when a thread accesses it for the first time, and it is accessible only by the thread that created it and gets destroyed when the thread terminates

* session-keyring(7) – it is a process keyring that survives across clone(2), fork(2) and execve(2) syscalls, sessions can be joined by processes or new sessions can be created, usually a session keyring is created when user logs in and destroyed when user logs out

## Key permissions

Since keys are sensitive information, those must be protected by permissions. Permissions are security attributes attached to keys. Keys as files are owned by a user ID and group ID. Then on top of that there is a bitmask of permissions which detemines what can be done with the key by user ID, group ID and others. The permissions are:

* read – the key can be read
* write – the key can be written
* search – the key can be searched
* link – the key can be linked to a keyring
* setattr – the key attributes like owner, group, permission mask and timeout to be changed
* view – allows to view type description and other parameters

There’s also another access right called possessor which specifies rights granted if a key is determined to be possessed by the caller. keyctl(1) has a nice table which describes the access rights:

```bash
Possessor UID       GID       Other     Permission Granted
========  ========  ========  ========  ==================
01000000  00010000  00000100  00000001  View
02000000  00020000  00000200  00000002  Read
04000000  00040000  00000400  00000004  Write
08000000  00080000  00000800  00000008  Search
10000000  00100000  00001000  00000010  Link
20000000  00200000  00002000  00000020  Set Attribute
3f000000  003f0000  00003f00  0000003f  All
```

So suppose we want to give all privileges to UID and Possessor, and view + read to the others we would do set its permissions to 0x3f3f0303.

The kernel exposes key information through the /proc/keys file and other multiple files described into keyrings(7) manpage. Let’s take a look at it

```bash
$ cat /proc/keys
05451ea7 I--Q---     4 perm 1f3f0000  1000 65534 keyring   _uid.1000: empty
14f7afae I--Q---     1 perm 1f3f0000  1000 65534 keyring   _uid_ses.1000: 1
293d8fc8 I--Q---    15 perm 3f030000  1000  1000 keyring   _ses: 1
3b3232a6 I--Q---   376 perm 3f030000  1000  1000 keyring   _ses: 1
```

The first column is the key ID, keys are represented as 32bit integers, in this view are formatted in hexadecimal. The second column shows flags, in this case all the keys are instantiated (I) and contribute to the user quota (Q). The third column tells how many struct cred are pinning that specific key, which approximately is the number of living threads and open files. The fourth column tells when the key will expire (all the keys here are marked as perm which means permanent). The fifth column is the permissions bitmask. The sixth column is the UID of the key owner. The seventh column is the GID of the key owner. The eighth column is the key type. The ninth column is the description of the key.

## How to use Linux Keyrings?

Linux provides a tool named keyctl which can be used to create/delete/update keys and keyrings. Let’s see how to use it.

```bash
# create a new keyring attached to the default session (@s) one, and name it my_keyring
# notice that @s is created on user login and destroyed on logout, the command returns
# the key ID of the newly created keyring
$  keyctl newring my_keyring @s
740991106

# show the default session keyring, notice that the keyring we created is attached to it
# along with the user keyring
$  keyctl show @s
Keyring
 993145510 --alswrv   1000  1000  keyring: _ses
  88415911 --alswrv   1000 65534   \_ keyring: _uid.1000
 740991106 --alswrv   1000  1000   \_ keyring: my_keyring

# add a new key (we generate it randomly with openssl) to the keyring we created,
# as for the keyring command, this command returns the key ID of the newly created key
$  keyctl add user my_key (openssl rand 32) 740991106
1032028779

# show the keyring again, notice that the key we created is attached to it
$  keyctl show @s
Keyring
 993145510 --alswrv   1000  1000  keyring: _ses
  88415911 --alswrv   1000 65534   \_ keyring: _uid.1000
 740991106 --alswrv   1000  1000   \_ keyring: my_keyring
1032028779 --alswrv   1000  1000       \_ user: my_key

# show the key we created
$ keyctl read 1032028779
32 bytes of data in key:
e2362872 8b32fc4f bb6eca6d 4f90be31 4b84a6ed cfd4535a c4d66991 0d2eb2bc

# we can also pipe data in raw format to other applications
$ keyctl pipe 1032028779 | hexyl
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ e2 36 28 72 8b 32 fc 4f ┊ bb 6e ca 6d 4f 90 be 31 │×6(r×2×O┊×n×mO××1│
│00000010│ 4b 84 a6 ed cf d4 53 5a ┊ c4 d6 69 91 0d 2e b2 bc │K×××××SZ┊××i×_.××│
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```

Before we move on with Go code, we’re going to show another example to compute Diffie-Hellman directly using keyrings feature.

This is our private key in hex

```bash
0f6f7590dcee920ca7a1f9dc8ff94e
87e4484b223d1fd57d3ee00a2f4616
a03a0152cafa5289676aed7291c75b
b031b4357a75698129dfbb4ca5e799
a34c545b8fe77fb5926e9184222a08
30f916ac7aef551c5fcd67722595df
aaa6098595a190bd461bee0ee9bbb0
1ea9ef24f3590ec3b036862c787e16
b855bfb05863083b99bd7de0dcae78
9422c87f6f030a02818b1ae63b7f1e
b6c6036de0a6b7f653c000cc1d0c54
7ecb9c5c0da71f5fafe7dd1c88fba7
35266bc0768043ba86fc86e8a41625
55ccc2e6806d882964997ea87533a2
37b0c617cb222c90418ded933e9eee
fa462dd0157471b24612d4c8622650
60
```

This is our prime module

```bash
fe4e0bd59f860a8eda80ad8663ad1d
3b55e19670a1a43d9e203428ca2794
ba934cb8d6ba2233faf96ef6c6a14a
5267de1d46108cf9341f0e1959bb54
2197d18076b51ceab3a249b2eacf13
2e453c64b4cdd089c295d2eda1200f
9f34627f5b7c3462a94f6e66ba6d5d
5f253d4420343a095ace2d1e10e194
0e291dda82557d89903683799bb4b8
f777a5471cbd1e452f3a8f8bb12347
f1f93e7da6f37f0f2b598c5eea2481
7c5a00197012e8b2c269c294d6de0b
853b25517f6d33e861fae1df79bda9
96785b5fc1527dafdd25a9d369c2d1
3714be41e9ee78080b7f9e5bb7a056
564c14cf5567b8b32eb1caa0579df2
301f
```

And this is our generator

```bash
02
```

So lets say we want to generate our public key doing `(generator ^ private_key) mod prime_module`, we can do it with the following code. Notice that in this example before loading our parameters and key we need to generate those. This can be achievied with openssl as follows:

```bash
openssl dhparam -check -out dh.pem 2048
openssl genpkey -paramfile dh.pem -text
```

Then you’ve to adjust a bit the format like removing the ‘:’ between hex bytes and then exporting the values e.g., as environment variables (do not forget to unset once loaded in the keyring, otherwise we’re voiding the purpose of using keyrings). Moreover consider this is just an example using the keyctl commandline tool, we could achieve the same result using APIs.

Once we’ve our params as env variable we can proceed with the following commands:

```bash
# we first load the prime module, the private key and the generator in the keyring
keyctl add user prime $prime @s
261425615

keyctl add user priv_key $priv_key @s
195168655

keyctl add user generator $generator @s
688070769

# lets show the keyring
keyctl show @s
Keyring
 611679097 --alswrv   1000  1000  keyring: _ses
 504006137 --alswrv   1000 65534   \_ keyring: _uid.1000
 688070769 --alswrv   1000  1000   \_ user: generator
 195168655 --alswrv   1000  1000   \_ user: priv_key
 261425615 --alswrv   1000  1000   \_ user: prime

# we then compute the public key doing 'keyctl dh_compute <private> <prime> <base>'
keyctl dh_compute 195168655 261425615 688070769
520 bytes of data in result:
00000000 00001b1c 0babf483 2a611efd 3051e63d 03d3f202 c2707669 5fc00072
64bbfbef 40ab3706 b59ac8ae 2402f65f 69a96dd0 a1569c65 13f6b9fc 45f9d810
d0229ba8 fcaed84d bce5a67e 32d0dac5 1e21c838 65f71921 ce6e07e4 72ae49b3
7b26c507 8ec0c502 776946d8 06f2aac7 9cabe6fe bca5edd3 58e861ab 6099a39f
d1c703cd a0b677d3 5fbd1e99 d80ec614 5ea1273d bcd8ce1a 93a0499f 485545a3
eaeb6630 f4d30a3f 22ba90fa b415b6a2 aa4772ca d28f11e1 729625f5 13dde521
af21aaf9 4746d52a 08e65b29 3982e708 4f3ba400 cfc5decb 45c2409f a0c12987
d38d5ac9 8e8cdcad 0777b523 c36e2526 659fbce2 06e385a4 d9379ba4 7343dbca
0df0db4a 4df84609 dc57bb99 16a75023 8596d4b1 26e4a9aa ec3a7187 b0f44ba0
283472cf 9a33c5be 32ee170c c190c649 9805d24c 8071b810 d535cf2b 8937eb43
10456d83 f978d7de ca222f30 74386a86 df76e34f c71328f6 f49e6a0e 36b540f3
35dac266 cbb86490 dfa3cf7a 45889447 b7aed36d de1a2ac2 0222bc6f 5a4ec429
04caac37 fbedfc99 913c593c 55908c07 760d5fd2 105d63f1 febfd782 fd62ef9d
c2e1bf99 e2e759cc 5eddbe74 29dd68b7 f37143e7 9a84e4e3 209f8ba1 cbc42e48
e4ecf652 7ce86b21 f3bf6d32 22843038 2095ae19 4b39679c 33fecad3 f393b057
60457f3d 8e68c024 505d9ae2 edb25a2b 111663a5 905b2d3f 629c749c a64659e0
910d1a7b 6432833c
```

## Using Keyrings in Go

In the following Go example code, we illustrate how we can use keyring facilities to store an ED25519 private key. The key is then used to sign and verify (with its public counterpart) a payload. We’re going to use the golang/x/unix package to interact with the kernel keyring, as it provides syscalls wrappers, and the crypto/ed25519 package to create/parse keys, sign and verify the payload.

The Go code, creates an HTTP service which exposes two endpoints:

* /generate → forges a simple JSON payload with some data and its ED25519 base64 encoded signature e.g,:

```json
{
  "payload":"some_data_1693390750",
  "signature":"QO1mZet+wpgODp+fs8PbfHvKqYBrX2OGxfxDyT8e+tH7DBVyBUafFNCTCbEiFrhm0urgrON9GkQBdv/0REpIBw=="
}
```

* /verify → accepts the above payload computes the payload field signature and compares it with the one in the signature field

When the service bootstraps it generates a new ED25519 key and stores it in the process keyring, then it sets the permissions on the keyring and on the key so that it can be accessed by other threads in the process. The the endpoints described above make use of some utilities functions to retrieve and use the key to perform sign and verify.

```go
package main

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"log/slog"

	"golang.org/x/sys/unix"
)

const (
    // this is the description of the key we're going to store in the keyring
	keyName = "priv_ed25519_key"
)

var (
    // this is our process keyring ID
    // it initialized in main()
	ringId = 0
)

// ServicePayload is the payload we're going to use to communicate with the service
type ServicePayload struct {
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
}

func main() {
    // get id of the process keyring or create a new one if it does not exist
    // check keyctl(2) KEYCTL_GET_KEYRING_ID
	var err error
	ringId, err = unix.KeyctlGetKeyringID(unix.KEY_SPEC_PROCESS_KEYRING, true)
	if err != nil {
		log.Fatal(err)
	}

    // set following permissions to the keyring:
	// * possesor all
    // * process with possessor uid view/read/search
    // check keyctl(2) KEYCTL_SETPERM
	err = unix.KeyctlSetperm(ringId, 0x3f0b0000)
	if err != nil {
		log.Fatal(err)
	}

    // generate a new key ED25519 key and store it in the keyring
	_, err = generateAndStorePrivKey(ringId)
	if err != nil {
		log.Fatal(err)
	}

    // start our HTTP service
	startService()
}

// retrievePrivKeyID retrieves the key ID of the private key stored in the keyring `ring`
func retrievePrivKeyID(ring int) (int, error) {
	return unix.KeyctlSearch(ring, "user", keyName, 0)
}

// generateAndStorePrivKey generates a new ED25519 key and stores it in the keyring `ring`
func generateAndStorePrivKey(ring int) (int, error) {
    // first generate a new ed25519 key
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return -1, err
	}

    // get the seed key and store it in the keyring
    // we'll use it later when needed to generate the ed25519 key
    // from it and sign the payload
	seed := priv.Seed()

    // store the seed in the keyring
    // check add_key(2)
	id, err := unix.AddKey("user", keyName, seed, ring)
    if err != nil {
        return -1, err
    }

	// set the permissions of the key, same as the keyring
	err = unix.KeyctlSetperm(id, 0x3f0b0000)
	if err != nil {
		return -1, err
	}

	return id, nil
}

// getKeyPayload retrieves the key payload from the keyring
func getKeyPayload(keyID int) ([]byte, error) {
    // create a buffer with the appropriate size
    // of the key seed
	buf := make([]byte, ed25519.SeedSize)

    // then read the key payload, which is the seed, this wrapper provides a way
    // to store the key in the buffer
    // check keyctl(2) KEYCTL_READ
	_, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// signPayload signs the data with the key stored in the keyring and returns the signature
func signPayload(data []byte, ring int) ([]byte, error) {
    // retrieve the key ID of the private key stored in the keyring
	keyID, err := retrievePrivKeyID(ring)
	if err != nil {
		return nil, err
	}

    // retrieve the key payload from the keyring
	keySeed, err := getKeyPayload(keyID)
	if err != nil {
		return nil, err
	}

    // setup the signer options
	opts := crypto.SignerOpts(crypto.Hash(0))

    // generate back the ed25519 key from the seed
    // and ask it to sign the data
	privKey := ed25519.NewKeyFromSeed(keySeed)
	sig, err := privKey.Sign(nil, data, opts)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// verifyPayload verifies the signature of the data with the public key stored in the keyring
func verifyPayload(data, sig []byte, ring int) (bool, error) {
    // retrieve the key ID of the private key stored in the keyring
	keyID, err := retrievePrivKeyID(ring)
	if err != nil {
		return false, err
	}

    // retrieve the key payload from the keyring
	keySeed, err := getKeyPayload(keyID)
	if err != nil {
		return false, err
	}

    // generate back the ed25519 key from the seed
    // and ask it to verify the data
	pubKey := ed25519.NewKeyFromSeed(keySeed).Public().(ed25519.PublicKey)

    // verify the signature
	if !ed25519.Verify(pubKey, data, sig) {
		return false, err
	}

	return true, nil
}

// startService starts the HTTP service which exposes two endpoints:
// * /generate - generates a new payload and signs it with the key stored in the keyring
// * /verify - verifies the signature of the payload with the public key stored in the keyring
func startService() {
	http.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
        // create some data attached to the current timestamp in unix seconds
		data := fmt.Sprintf("some_data_%d", time.Now().Unix())

        // sign the data with the key stored in the keyring
		sig, err := signPayload([]byte(data), ringId)
		if err != nil {
			slog.Error("failed to generate signature", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

        // encode the signature in base64 so that it can be sent over the wire
		b64Sig := base64.StdEncoding.EncodeToString(sig)
		payload := ServicePayload{
			Signature: b64Sig,
			Payload:   data,
		}

        // encode the payload in JSON
		buf, err := json.Marshal(payload)
		if err != nil {
			slog.Error("failed to marshal payload", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

        // adjust content type and write the response
		w.Header().Add("Content-Type", "application/json")
		_, err = w.Write(buf)
		if err != nil {
			slog.Error("failed to write response", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
        // decode the payload from JSON
		var payload ServicePayload
		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			slog.Error("failed to decode payload", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

        // decode the signature from base64 to bytes
		sig, err := base64.StdEncoding.DecodeString(payload.Signature)
		if err != nil {
			slog.Error("failed to decode signature", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

        // verify the signature with the public key stored in the keyring
		res, err := verifyPayload([]byte(payload.Payload), sig, ringId)
		if err != nil {
			slog.Error("failed to execute payload verification", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

        // if the signature is not valid, return 401
		if !res {
			slog.Error("failed to verify payload", "error", res)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		slog.Info("payload verified", "payload", payload.Payload)
	})

	http.ListenAndServe(":8080", nil)
}
```

Now we can test our service with curl:

```bash
# we ask our service to generate a new payload along with its signature
curl  -v '<http://localhost:8080/generate'> | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /generate HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.0.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Content-Type: application/json
< Date: Mon, 28 Aug 2023 13:21:08 GMT
< Content-Length: 137
< 
{ [137 bytes data]
100   137  100   137    0     0   238k      0 --:--:-- --:--:-- --:--:--  133k
* Connection #0 to host localhost left intact
{
  "signature": "QO1mZet+wpgODp+fs8PbfHvKqYBrX2OGxfxDyT8e+tH7DBVyBUafFNCTCbEiFrhm0urgrON9GkQBdv/0REpIBw==",
  "payload": "some_data_1693228868"
}

# now we can verify the signature with the /verify endpoint, it returns 200 if the signature is valid
curl -v '<http://localhost:8080/verify'> --data '{"signature":"QO1mZet+wpgODp+fs8PbfHvKqYBrX2OGxfxDyT8e+tH7DBVyBUafFNCTCbEiFrhm0urgrON9GkQBdv/0REpIBw==", "payload":"some_data_1693228868"}'
*   Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080 (#0)
> POST /verify HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.0.1
> Accept: */*
> Content-Length: 138
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 200 OK
< Date: Mon, 28 Aug 2023 13:22:14 GMT
< Content-Length: 0
< 
* Connection #0 to host localhost left intact

# let's try to verify with a different payload, e.g. changing the last digit to 9 in payload
curl -v '<http://localhost:8080/verify'> --data '{"signature":"QO1mZet+wpgODp+fs8PbfHvKqYBrX2OGxfxDyT8e+tH7DBVyBUafFNCTCbEiFrhm0urgrON9GkQBdv/0REpIBw==", "payload":"some_data_1693228869"}'
*   Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080 (#0)
> POST /verify HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.0.1
> Accept: */*
> Content-Length: 138
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 401 Unauthorized
< Date: Mon, 28 Aug 2023 13:23:03 GMT
< Content-Length: 0
< 
* Connection #0 to host localhost left intact
```

## Conclusion

In this article we’ve seen how to use Linux Keyrings to store sensitive information such as keys. We’ve seen how to use the keyctl commandline tool to create/delete/update keys and keyrings. Then we’ve seen how to use the golang/x/unix package to interact with the kernel keyring, as it provides syscalls wrappers, and the crypto/ed25519 package to create/parse keys, sign and verify the payload. It is a lot of material to digest, but it is worth to improve security of our applications, and moreover it is fun to learn new things! Please consider that we scratched the surface of a huge topic, so the motivated person is encouraged to go through man pages and dive deeper into the topic.