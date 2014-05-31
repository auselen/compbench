#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/lzo.h>

struct algorithm {
    const char *name;
    void *(*init)(void);
    void (*deinit)(void *data);
    int (*f)(const unsigned char *in, size_t in_size,
             unsigned char *out, size_t *out_size,
             void *data);
};

#ifdef CONFIG_LZO_COMPRESS
static void *algo_lzo_compress_init(void) {
    return kzalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
}

static void algo_lzo_compress_deinit(void *data) {
    kfree(data);
}

static int algo_lzo_compress(const unsigned char *in, size_t in_size,
                    unsigned char *out, size_t *out_size,
                    void *data) {
    int ret;
    ret = lzo1x_1_compress(in, in_size, out, out_size, data);
    return ret == LZO_E_OK ? 0 : ret;
}
#endif

static struct algorithm algorithms[] = {
#ifdef CONFIG_LZO_COMPRESS
    {"comp_lzo", algo_lzo_compress_init, algo_lzo_compress_deinit, algo_lzo_compress},
#endif
    {NULL, NULL}
};

static char *inbuf;
static int inbuf_size;
static struct algorithm *algo = algorithms;

static void calc_checksums(char *buf)
{
    struct crypto_hash *tfm;
    struct hash_desc desc;
    struct scatterlist sg;
    char sha1[40];
    int i;
    int ret;

    tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        return;
    }

    desc.tfm = tfm;
    desc.flags = 0;

    ret = crypto_hash_init(&desc);
    if (ret < 0)
        goto out;

    sg_init_one(&sg, inbuf, inbuf_size);
    ret = crypto_hash_update(&desc, &sg, inbuf_size);
    if (ret < 0)
        goto out;

    ret = crypto_hash_final(&desc, sha1);
    if (ret < 0)
        goto out;

    for (i = 0; i < 20; i++) {
        sprintf(&buf[i * 2], "%02x", sha1[i] & 0xff);
    }

    out:
    crypto_free_hash(tfm);
}


static ssize_t avail_show(struct kobject *kobj, struct kobj_attribute *attr,
                          char *buf)
{
    int i = 0;
    struct algorithm *e = algorithms;

    while (e->name != NULL) {
        if (i > 0)
            i += sprintf(buf + i, ", ");
        i += sprintf(buf + i, e->name);
        e++;
    }
    i += sprintf(buf + i, "\n");

    return i;
}

static struct kobj_attribute avail_attribute =
    __ATTR_RO(avail);

static ssize_t in_store(struct file *filp, struct kobject *kobj,
                        struct bin_attribute *bin_attr,
                        char *buf, loff_t pos, size_t count)
{
    inbuf_size = 0;
    inbuf = krealloc(inbuf, pos + count, GFP_ATOMIC);
    if (inbuf) {
        memcpy(inbuf + pos, buf, count);
        inbuf_size = pos + count;
    }
    return count;
}

BIN_ATTR(in, S_IWUGO, NULL, in_store, 0);

static ssize_t stat_show(struct kobject *kobj, struct kobj_attribute *attr,
                          char *buf)
{
    size_t out_size = 0;
    unsigned long op_time = 0;
    char inbuf_sha1[41];

    memset(inbuf_sha1, 0x0, sizeof(inbuf_sha1));
    calc_checksums(inbuf_sha1);

    if (algo->name != NULL && inbuf_size > 0) {
        struct timeval start, end;
        char *out = kmalloc(inbuf_size + PAGE_SIZE, GFP_KERNEL);
        if (out) {
            void *d = algo->init();
            do_gettimeofday(&start);
            algo->f(inbuf, inbuf_size, out, &out_size, d);
            do_gettimeofday(&end);
            op_time = (end.tv_sec - start.tv_sec) * USEC_PER_SEC +
                      (end.tv_usec - start.tv_usec);
            algo->deinit(d);

            kfree(out);
        }
    }

    return sprintf(buf,
                   "buffer size: %d\n"
                   "buffer sha1: %s\n"
                   "output size: %zu\n"
                   "algorithm: %s\n"
                   "last op time: %lu\n",
                   inbuf_size,
                   inbuf_sha1,
                   out_size,
                   algo->name ? algo->name : "<not selected>",
                   op_time
                   );
}

static struct kobj_attribute stat_attribute =
    __ATTR_RO(stat);

static struct attribute *attrs[] = {
    &avail_attribute.attr,
    &stat_attribute.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};

static struct kobject *cb_kobj;

static int __init compbench_init(void)
{
    int retval;

    cb_kobj = kobject_create_and_add("compbench", kernel_kobj);
    if (!cb_kobj)
        return -ENOMEM;

    retval = sysfs_create_group(cb_kobj, &attr_group);
    if (retval)
        goto err;

    retval = sysfs_create_bin_file(cb_kobj, &bin_attr_in);
    if (retval)
        goto err;

    goto success;

    err:
    kobject_put(cb_kobj);
    success:
    return retval;
}

static void __exit compbench_cleanup(void)
{
    sysfs_remove_bin_file(cb_kobj, &bin_attr_in);
    kobject_put(cb_kobj);
}

module_init(compbench_init);
module_exit(compbench_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ali Utku Selen");
MODULE_DESCRIPTION("Compression module benchmarker");
