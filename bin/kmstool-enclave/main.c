#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>

#include <json-c/json.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#define SERVICE_PORT 3000
#define PROXY_PORT 8000

AWS_STATIC_STRING_FROM_LITERAL(default_region, "us-east-1");

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, label, msg)                                                                                      \
    if (cond) {                                                                                                        \
        err_msg = NULL;                                                                                                \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
            err_msg = msg;                                                                                             \
        }                                                                                                              \
        goto label;                                                                                                    \
    }

#define break_on(cond)                                                                                                 \
    if (cond) {                                                                                                        \
        break;                                                                                                         \
    }

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;
    /* KMS region to use. */
    const struct aws_string *region;
    /* vsock port on which to open service. */
    uint32_t port;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;
    /* alternative kms endpoint hostname */
    const struct aws_string *kms_endpoint;
};


static void s_parse_options(struct app_ctx *ctx) {
    ctx->port = SERVICE_PORT;
    ctx->proxy_port = PROXY_PORT;
    ctx->region = aws_string_new_from_c_str(ctx->allocator, "us-east-1");
    ctx->kms_endpoint = aws_string_new_from_c_str(ctx->allocator, "kms.us-east-1.amazonaws.com");
}

struct aws_credentials *s_read_credentials(struct aws_allocator *allocator, struct json_object *object) {
    struct aws_credentials *credentials = NULL;

    struct json_object *aws_access_key_id = json_object_object_get(object, "AwsAccessKeyId");
    struct json_object *aws_secret_access_key = json_object_object_get(object, "AwsSecretAccessKey");
    struct json_object *aws_session_token = json_object_object_get(object, "AwsSessionToken");

    credentials = aws_credentials_new(
        allocator,
        aws_byte_cursor_from_c_str(json_object_get_string(aws_access_key_id)),
        aws_byte_cursor_from_c_str(json_object_get_string(aws_secret_access_key)),
        aws_byte_cursor_from_c_str(json_object_get_string(aws_session_token)),
        UINT64_MAX);

    return credentials;
}

/**
 * This function returns the AWS region the client will use, with the following
 * rules:
 * 1. If a region is already set at the start of this program it will return it, unless
 * the client also wants to set a region, in which case it will return NULL, since
 * the client and the enclave collide in requirements.
 * 2. If a region is not set at the start of this program, and the client sets one,
 * then the client one is returned, if it's correctly set by the client.
 * 3. If no region is set at either the start of this program, nor by the client,
 * then default_region is returned.
 */
struct aws_string *s_read_region(struct app_ctx *ctx, struct json_object *object) {
    struct json_object *aws_region = json_object_object_get(object, "AwsRegion");
    /* Neither is set, so use default_region */
    if (aws_region == NULL && ctx->region == NULL) {
        return aws_string_clone_or_reuse(ctx->allocator, default_region);
    }

    /* Both are set, don't allow it. */
    if (aws_region != NULL && ctx->region != NULL) {
        return NULL;
    }

    /* Enclave is set. */
    if (aws_region == NULL && ctx->region != NULL) {
        return aws_string_clone_or_reuse(ctx->allocator, ctx->region);
    }

    /* AwsRegion is set, verify it. */
    if (!json_object_is_type(aws_region, json_type_string))
        return NULL;

    return aws_string_new_from_c_str(ctx->allocator, json_object_get_string(aws_region));
}

static const char * handle_connection(struct app_ctx *app_ctx, struct json_object *object) {
    ssize_t rc = 0;
    char *err_msg = NULL;

    struct aws_credentials *credentials = NULL;
    struct aws_string *region = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = "3", .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator,
        .endpoint = &endpoint,
        .domain = AWS_SOCKET_VSOCK,
        .host_name = app_ctx->kms_endpoint,
    };

    fail_on(object == NULL, loop_next_err, "Error reading JSON object");
    fail_on(!json_object_is_type(object, json_type_object), loop_next_err, "JSON is wrong type");

    struct json_object *awsAccessKeyId = json_object_object_get(object, "AwsAccessKeyId");
    fail_on(awsAccessKeyId == NULL, loop_next_err, "JSON structure incomplete");
    fail_on(!json_object_is_type(awsAccessKeyId, json_type_string), loop_next_err, "AwsAccessKeyId is wrong type");

    /* SetClient operation sets the AWS credentials and optionally a region and
     * creates a matching KMS client. This needs to be called before Decrypt. */
    struct aws_credentials *new_credentials = s_read_credentials(app_ctx->allocator, object);
    fail_on(new_credentials == NULL, loop_next_err, "Could not read credentials");

    /* If credentials or client already exists, replace them. */
    if (credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);
    }

    if (aws_string_is_valid(region)) {
        aws_string_destroy(region);
        region = NULL;
    }
    region = s_read_region(app_ctx, object);
    fail_on(region == NULL, loop_next_err, "Could not set region correctly, check configuration.");

    credentials = new_credentials;
    configuration.credentials = new_credentials;
    configuration.region = region;
    client = aws_nitro_enclaves_kms_client_new(&configuration);

    fail_on(client == NULL, loop_next_err, "Could not create new client");

    /* Decrypt uses KMS to decrypt the data passed to it in the CipherText
     * field and sends it back to the called*
     * TODO: This should instead send a hash of the data instead.
     */
    fail_on(client == NULL, loop_next_err, "Client not initialized");

    struct json_object *operation_obj = json_object_object_get(object, "Operation");
    fail_on(operation_obj == NULL, loop_next_err, "Message does not contain an Operation");
    fail_on(!json_object_is_type(operation_obj, json_type_string), loop_next_err, "Operation is not a string");

    const char *operation = json_object_get_string(operation_obj);

    if (strcmp(operation, "Decrypt") == 0) {
        struct json_object *ciphertext_obj = json_object_object_get(object, "CipherText");
        fail_on(ciphertext_obj == NULL, loop_next_err, "Message does not contain a CipherText");
        fail_on(
            !json_object_is_type(ciphertext_obj, json_type_string),
            loop_next_err,
            "CipherText not a base64 string");

        /* Get decode base64 string into bytes. */
        size_t ciphertext_len;
        struct aws_byte_buf ciphertext;
        struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str(json_object_get_string(ciphertext_obj));

        rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "CipherText not a base64 string");
        rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Memory allocation error");
        rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "CipherText not a base64 string");

        /* Decrypt the data with KMS. */
        struct aws_byte_buf ciphertext_decrypted;
        rc = aws_kms_decrypt_blocking(client, NULL, NULL, &ciphertext, &ciphertext_decrypted);
        aws_byte_buf_clean_up(&ciphertext);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not decrypt ciphertext");
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);
        return (const char *)ciphertext_decrypted.buffer;
    } else if (strcmp(operation, "Sign") == 0) {
        struct json_object *key_id = json_object_object_get(object, "KeyId");
        fail_on(key_id == NULL, loop_next_err, "Message does not contain KeyId");

        const struct aws_string *key_id_aws_string = aws_string_new_from_c_str(app_ctx->allocator, json_object_get_string(key_id));

        enum aws_signing_algorithm signing_algorithm = AWS_SA_ECDSA_SHA_256;
        enum aws_message_type message_type = AWS_MT_RAW; 

        // Extract the base64 encoded message from the JSON object
        struct json_object *message_obj = json_object_object_get(object, "Message");
        fail_on(message_obj == NULL, loop_next_err, "Message does not contain a Message field");
        fail_on(!json_object_is_type(message_obj, json_type_string), loop_next_err, "Message not a base64 string");

        /* Get decode base64 string into bytes. */
        size_t message_len;
        struct aws_byte_buf message;
        struct aws_byte_cursor message_b64 = aws_byte_cursor_from_c_str(json_object_get_string(message_obj));

        rc = aws_base64_compute_decoded_len(&message_b64, &message_len);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Message not a base64 string");
        rc = aws_byte_buf_init(&message, app_ctx->allocator, message_len);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Memory allocation error");
        rc = aws_base64_decode(&message_b64, &message);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Message not a base64 string");

        // Further processing, such as the call to aws_kms_sign_blocking
        struct aws_byte_buf signature;
        rc = aws_kms_sign_blocking(client, key_id_aws_string, signing_algorithm, &message, message_type, &signature);
        aws_byte_buf_clean_up(&message);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not Sign message");
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);

        return (const char *)signature.buffer;
    } else if (strcmp(operation, "GetPublicKey") == 0) {

        struct json_object *key_id = json_object_object_get(object, "KeyId");
        fail_on(key_id == NULL, loop_next_err, "Message does not contain KeyId");

        const struct aws_string *key_id_aws_string = aws_string_new_from_c_str(app_ctx->allocator, json_object_get_string(key_id));
        fail_on(key_id_aws_string == NULL, loop_next_err, "Memory allocation error");

        struct aws_byte_buf pub_key;
        rc = aws_kms_get_public_key_blocking(client, key_id_aws_string, &pub_key);
        fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not get public key");
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);

        return (const char *)pub_key.buffer;
    }

loop_next_err:
    json_object_put(object);
    object = NULL;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./kmstool-enclave <input JSON string>\n");
        return -1;
    }
    json_object *root_obj = json_tokener_parse(argv[1]);

    struct json_object *ackd = json_object_object_get(root_obj, "AwsAccessKeyId");
    //fprintf(stdout, "AwsAccessKeyId: %s\n",json_object_to_json_string(ackd));

    struct app_ctx app_ctx;
    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();
    s_parse_options(&app_ctx);

    /* Set region if not already set and  */
    if (app_ctx.region == NULL && getenv("REGION") != NULL && strlen(getenv("REGION")) > 0) {
        app_ctx.region = aws_string_new_from_c_str(app_ctx.allocator, getenv("REGION"));
    }

    /* Override KMS endpoint hostname */
    if (app_ctx.kms_endpoint == NULL && getenv("ENDPOINT") != NULL && strlen(getenv("ENDPOINT")) > 0) {
        app_ctx.kms_endpoint = aws_string_new_from_c_str(app_ctx.allocator, getenv("ENDPOINT"));
    }

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);
    const char* decryptedText = handle_connection(&app_ctx, root_obj);
    printf("Content: %s\n", decryptedText);
    aws_nitro_enclaves_library_clean_up();
    return 0;
}

