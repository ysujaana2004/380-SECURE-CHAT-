
#include <unistd.h>
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include <openssl/rand.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

unsigned char shared_key[32];  // 256-bit AES key + HMAC key

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);  //updates the text buffer (GUI)
	
	//Gets the full message typed by the user from the GTK text buffer (mbuf).

	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = strlen(message);  // (openssl) counts actual bytes  needed for encryption).
	
	//size_t len = g_utf8_strlen(message,-1);

	//updated
	// encrypt message using AES-256-CTR
	unsigned char iv[16];
	RAND_bytes(iv, sizeof(iv));   //generate randomn IV (Initialization Vector)

	unsigned char ciphertext[1024];
	int outlen;

	/*
	EVP stands for Envelope in OpenSSL’s high-level cryptographic API

	using it for AES-256-CTR encryption && decryption, HMAC-SHA256
	*/
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, shared_key, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)message, len);
	EVP_CIPHER_CTX_free(ctx); 

	// create IV || ciphertext for HMAC input
	unsigned char payload[16 + outlen];
	memcpy(payload, iv, 16);
	memcpy(payload + 16, ciphertext, outlen);

	// comput HMAC over IV || ciphertext
	unsigned int maclen = 32; // SHA-256 = 32 bytes
	unsigned char mac[32];
	HMAC(EVP_sha256(), shared_key, 32, payload, 16 + outlen, mac, &maclen);

//  send IV || ciphertext || HMAC
	unsigned char final_payload[16 + outlen + maclen];
	memcpy(final_payload, iv, 16);
	memcpy(final_payload + 16, ciphertext, outlen);
	memcpy(final_payload + 16 + outlen, mac, maclen);


	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes = send(sockfd, final_payload, sizeof(final_payload), 0);
	if (nbytes == -1)
		error("send failed");

	
	tsappend(message, NULL, 1);  //display message in the chat view
	free(message);

	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);

	/*
	for testing. Prints the raw ciphertext in hexadecimal. This is for me to check if encryption actully worked 
	*/
	printf("Ciphertext (hex): ");
	for (int i = 0; i < outlen; i++) printf("%02x", ciphertext[i]);
	printf("\n");

}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0); // Turn off stdout buffering
	// IONBF == no buffering at all 

	/*
	C buffers output to reduce syscalls (it waits to print until a newline or flush). 
	but in GUI apps like GTK, stdout can get swallowed or stuck unless forced out.

	THIS WASSS A PAINFUL ISSUE
	*/
	printf("HELLO FROM MAIN\n");  //this is just to make sure that the app is entering the main() and not crashing early
	fflush(stdout);


	/*
	tries to initialize your Diffie-Hellman (DH) parameters from a file called "params
	This make sures that your app doesn't continue if it can't securely perform the key exchange.
	*/

	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}

	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname, port);
	} else {
		initServerNet(port);
	}

	// Common declarations
	mpz_t peer_pubkey;
	unsigned char sig[512];
	size_t siglen;

	dhKey myKey;
	dhGenk(&myKey);  // generate DH key pair (needed by server and client)

	if (!isclient) {
		// Server: Receive, Verify, Send

		// receive client's DH public key + signature
		if (recv_dh_pubkey_with_sig(sockfd, &peer_pubkey, sig, &siglen) != 0) {
			fprintf(stderr, "Failed to receive peer DH pubkey and signature\n");
			exit(EXIT_FAILURE);
		}

		gmp_printf("Server received DH pubkey: %Zd\n", peer_pubkey);

		if (!verify_dh_pubkey(peer_pubkey, sig, siglen, "alice_pub.pem")) {
			fprintf(stderr, "Signature verification failed.\n");
			exit(EXIT_FAILURE);
		}

		// sign and send DH key
		if (send_dh_pubkey_with_sig(sockfd, myKey.PK, "bob_priv.pem") != 0) {
			fprintf(stderr, "Failed to send authenticated DH public key\n");
			exit(EXIT_FAILURE);
		}

		// compute shared secret
		dhFinal(myKey.SK, myKey.PK, peer_pubkey, shared_key, 32);
		printf("Server: Shared key established.\n");

	} 
	else {
		// Client: Send, Receive, Verify

		// send DH public key + signature
		if (send_dh_pubkey_with_sig(sockfd, myKey.PK, "alice_priv.pem") != 0) {
			fprintf(stderr, "Failed to send authenticated DH public key\n");
			exit(EXIT_FAILURE);
		}

		gmp_printf("Client sent DH pubkey: %Zd\n", myKey.PK);

		// receive server's DH key + signature
		if (recv_dh_pubkey_with_sig(sockfd, &peer_pubkey, sig, &siglen) != 0) {
			fprintf(stderr, "Failed to receive server's DH key\n");
			exit(EXIT_FAILURE);
		}

		if (!verify_dh_pubkey(peer_pubkey, sig, siglen, "bob_pub.pem")) {
			fprintf(stderr, "Server signature verification failed.\n");
			exit(EXIT_FAILURE);
		}

		// compute shared secret
		dhFinal(myKey.SK, myKey.PK, peer_pubkey, shared_key, 32);
		printf("Client: Shared key established.\n");
	}


	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv, 0, recvMsg, 0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	} else {

		printf("recvMsg thread started.\n");
		fflush(stdout);
	}
	

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */

 /* updating recMsg to read first 16 bytes as the IV and then 
     decrypt the cyphertect using the same shared key */  //suj//

void* recvMsg(void*)
{

	// IV + ciphertext + HMAC

	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	char* tags[] = {"status", NULL};



	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			tsappend("Receiver disconnected.\n", tags, 1);
			return 0;
		}
		
		if (nbytes < 48) //16+32
			continue; // checks for invalid message length

	unsigned char* iv = msg;
	unsigned char* ciphertext = msg + 16;
	int ctlen = nbytes - 16 - 32; // total - IV - HMAC
	unsigned char* received_mac = msg + 16 + ctlen;
	
	// Recompute HMAC over IV + ciphertext
	unsigned char expected_mac[32];
	unsigned int maclen = 32;
	HMAC(EVP_sha256(), shared_key, 32, msg, 16 + ctlen, expected_mac, &maclen);
	
	// Compare MACs
	if (CRYPTO_memcmp(received_mac, expected_mac, 32) != 0) {
		tsappend("WARNING: Message failed integrity check.\n", tags, 1);
		
		continue; // Don't decrypt or display!
	}
	
//UPDATE-start
		unsigned char plaintext[512];
		int outlen;

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, shared_key, iv);
		EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ctlen);
		EVP_CIPHER_CTX_free(ctx);


// update-end

		/*

		this simply receives plain  UTF-8 text directly into msg
		and we just copied it into m and printed it

		the actual readable message is not msg anymore. we have to
		decrypt it to get the plaintext so the length of the 
		message is outlen not nbytes
		//suj//

		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes);
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;

		*/

		char* m = malloc(outlen + 1);             // Allocate JUST enough for decrypted text + null
		memcpy(m, plaintext, outlen);             // Copy decrypted text
		m[outlen] = '\0';                         // Null terminate it (SOOOOOO important!)


		g_main_context_invoke(NULL, shownewmessage, (gpointer)m);

		printf("Decrypted: %s\n", m);  // m is the null-terminated plaintext

	}
	return 0;
}