#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alon Balassiano");

struct class* fw_class = NULL;

static int __init module_init_function(void) 
{    
    // create a shared class
    fw_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(fw_class)) return -1;
    
    // initialize inspection hook in inspection.c
    if (init_inspection())
    {
        class_destroy(fw_class);
        return -1;
    }

    // initialize rules in rule.c
    if (init_rule_table()) 
    {
        release_inspection();
        class_destroy(fw_class);
        return -1;
    }
    
    // initialize logs in log.c
    if (init_log_module())
    {
        release_rule_table();
        release_inspection();
        class_destroy(fw_class);
        return -1;
    }

    // initialize connection table in conns.c
    if (init_conns())
    {
        release_log_module();
        release_rule_table();
        release_inspection();
        class_destroy(fw_class);
        return -1;
    }

    // initialize proxy/mitm in mitm.c
    if (init_mitm())
    {
        release_conns();
        release_log_module();
        release_rule_table();
        release_inspection();
        class_destroy(fw_class);
        return -1;
    }
    
    return 0;
}


static void __exit module_exit_function(void) 
{
    release_mitm();
    release_conns();	
    release_log_module();
    release_rule_table();
    release_inspection();
	class_destroy(fw_class);
}


module_init(module_init_function);
module_exit(module_exit_function);