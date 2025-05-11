// GCC reftrack plugin
// SPDX-License-Identifier: GPL-2.0-only
/************************************************************
Copyright (C) 2022-2023 Aravind Ceyardass (dev@aravind.cc)
************************************************************/

#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <cassert>
#include <cstring>
#include <functional>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

#include "gcc-plugin.h"
#include "basic-block.h"
#include "context.h"
#include "function.h"
#include "input.h"
#include "is-a.h"
#include "coretypes.h"
#include "dumpfile.h"
#include "plugin.h"
#include "timevar.h"
#include "tree-core.h"
#include "tree.h"
#include "tree-pass.h"
#include "context.h"
#include "gimple.h"
#include "gimple-expr.h"
#include "gimple-ssa.h"
#include "gimple-iterator.h"
#include "gimplify-me.h"
#include "tree-pass.h"
#include "stringpool.h"
#include "c-family/c-common.h"
#include "diagnostic-core.h"
#include "attribs.h"
#include "langhooks.h"

#include "reftrack.h"

using std::cout;
using std::endl;
using std::for_each;
using std::string;
using std::to_string;
using std::unordered_map;
using std::unordered_set;
using std::vector;


int plugin_is_GPL_compatible;

#define LOG(L, ...)                                                     \
    do {                                                                \
        if (logging(L))                                                 \
            log(L, {__VA_ARGS__});                                      \
    } while(0)

namespace reftrack {

    // A helper class
    class xstring : public string {
    public:
        xstring(const char *p) : string(p ? p : "<null>") {}
        xstring(int i) : string(to_string(i)) {}
        xstring(size_t n) : string(to_string(n)) {}
        xstring(void *p) : string(to_string((long)p)) {}
        xstring(const string& s) :string(s){}
    };


    enum log_level {TRACE = 1, DEBUG, WARN, INFO, ERROR};

    const char PLUGIN_NAME[] = "reftrack";

    const char REF_ATTR_NAME[] = "reftrack";

    const char REFTRACK_TMP_PREFIX[] = "reftrack_";

    const string horiz_line(60, '=');

    typedef struct {
        tree ref_add_fn;
        tree ref_remove_fn;
        tree pointer_type;
    } ref_info;


    typedef struct {
        enum gimple_code gcode;
        location_t loc;
        tree fn;
        tree var;
        bool use_tmp;
        tree tmp_type;
    } gimple_build_info;

    struct Globals {
        bool debug;
        struct plugin_info pinfo;
        vector<string> fn_list;
        int pass;

        // map from struct to ref function info
        unordered_map<const_tree, ref_info> ref_structs;

        // set of fields that have refcount attribute
        unordered_set<tree> refcount_fields;

        // skip reference tracking to function like malloc, alloc, free, etc.
        unordered_set<tree> ignored_fns;

        // list of destructor functions defined
        unordered_set<tree> destructor_fns;

        unordered_set<string> global_ignored_fns;

        log_level cur_log_level;

        // functions that needs to be replaced with reftrack version
        tree orig_alloc_fn, orig_free_fn;

        // name of the functions that needs to be replaced.
        string orig_alloc_fn_name, orig_free_fn_name;

        // functions that implement the reftrack malloc & free equivalents
        tree reftrack_alloc_fn, reftrack_free_fn;

        // name of the functions that implement the reftrack malloc & free equivalents

        string reftrack_alloc_fn_name, reftrack_free_fn_name;

        // default addref, removeref functions

        tree default_addref_fn, default_removeref_fn;

        // name of the default addref, removeref functions

        string default_addref_fn_name, default_removeref_fn_name;

        // replace malloc, free globally
        bool replace_memfn;

        // newline
        char nl;

        tree get_tree(const string& name){
            return lookup_name(get_identifier(name.c_str()));
        }

        tree get_orig_alloc_fn(){
            return orig_alloc_fn;
        }
        tree get_orig_free_fn(){
            return orig_free_fn;
        }
        tree get_reftrack_alloc_fn(){
            return reftrack_alloc_fn;
        }
        tree get_reftrack_free_fn(){
            return reftrack_free_fn;
        }
        tree get_default_addref_fn(){
            return default_addref_fn;
        }
        tree get_default_removeref_fn(){
            return default_removeref_fn;
        }

    };

    static struct Globals G = {
        .debug = true,
        .pinfo = {.version = "1.0.0",
            .help = "reftrack: list functions"
        },
        .pass = 0,
        .global_ignored_fns = {"memset", "free"},
        .cur_log_level = ERROR,
        .orig_alloc_fn_name = "malloc",
        .orig_free_fn_name = "free",
        .reftrack_alloc_fn_name = "rc_malloc_",
        .reftrack_free_fn_name = "rc_free_",
        .nl = '\n'
    };

    static const pass_data reftrack_data = {
        GIMPLE_PASS,
        "reftrack",
        OPTGROUP_NONE,
        TV_NONE,
        PROP_gimple_any,
        0,
        0,
        0,
        0
    };

    static const pass_data reftrack_cleanup_data = {
        GIMPLE_PASS,
        "reftrack_cleanup",
        OPTGROUP_NONE,
        TV_NONE,
        PROP_gimple_any,
        0,
        0,
        0,
        0
    };

    static inline string gimple_loc_str(const gimple *g){
        xstring rv{gimple_filename(g)};
        rv+=':';
        rv+=xstring(gimple_lineno(g));
        rv+=":0";
        return rv;

    }

    static inline bool logging(log_level l){ return l >= G.cur_log_level;}

    static inline void log(log_level level, const vector<xstring>& arg_list){

        if (logging(level)){
            bool first = true;

            for(const auto& x : arg_list){
                if (!first) { cout << ' '; }
                cout << x;
                first = false;
            }

            cout << G.nl;
        }
    }

     static inline bool is_generated(const_tree var){

         bool rv = var && (DECL_ARTIFICIAL(var)
                           || !DECL_NAME(var));
         return rv;
    }

    static inline string identifier_name(const_tree t){
        string rv;
        if (get_name((tree)t))
            rv = get_name((tree)t);
        return rv;
    }

    static inline string symbol_name(const_tree t) {
        string name = "?";

        if (!t)
            return "<null>";

        if (is_generated(t)){
            name = "G."+ xstring((size_t)DECL_UID(t));
        }
        else if (!identifier_name(t).size()){
            name = "U."+ xstring((size_t)DECL_UID(t));
        }
        else{
            name = identifier_name(t);
        }
        return name;
    }


    static bool is_call_arg(tree arg, gcall *callee){
        auto arg_count = gimple_call_num_args(callee);
        for(unsigned ai = 0; ai < arg_count; ai++){
            auto call_arg = gimple_call_arg(callee, ai);
            if (call_arg == arg)
                return true;
        }
        return false;
    }

    static inline string type_name(const_tree t) {
        string name {'?'};

        auto tcc = TREE_CODE_CLASS(TREE_CODE(t));
        auto tname = TYPE_NAME(t);

        if (tcc == tcc_type && tname) {
            if (TREE_CODE(tname) == IDENTIFIER_NODE)
                name = IDENTIFIER_POINTER(tname);
            else if (TREE_CODE(tname) == TYPE_DECL && DECL_NAME(tname))
                name = IDENTIFIER_POINTER(DECL_NAME(tname));
        }

        return name;
    }

    static inline bool is_static(const_tree var){
        return TREE_STATIC(var);
    }

    static inline bool is_array_elem(const_tree var){
        return TREE_CODE(var) == ARRAY_REF;
    }

    static inline bool is_component(const_tree var){
        return TREE_CODE(var) == COMPONENT_REF;
    }


    static inline string attr_name(const_tree t){
        string name;
        if (t){
            name = IDENTIFIER_POINTER(TREE_PURPOSE(t));
        }
        return name;
    }

    static inline bool null_value(const_tree var){
        return TREE_CODE(var) == INTEGER_CST && int_cst_value(var) == 0;
    }

    static inline string function_name(const_tree t){
        string name;
        if (DECL_NAME(t)){
            name = xstring(IDENTIFIER_POINTER(DECL_NAME(t)));
        }
        return name;
    }

    static inline bool is_ignored_function(tree fn){
        return G.ignored_fns.find(fn) != G.ignored_fns.end();
    }

    static string get_enclosing_type(const tree & t){
        string rv {""};

        auto et = decl_type_context(t);

        if (0 && et && IS_TYPE_OR_DECL_P(et)){
            auto& etype_ID = DECL_NAME(et);

            const char *name =
                (etype_ID ? IDENTIFIER_POINTER(etype_ID) : "");
            rv = name;
        }
        return rv;
    }

    // returns the type name of the given type
    static string c_type_name(const_tree ttype) {
        string tname;
        int tcode = TREE_CODE(ttype);

        switch (tcode) {

        case POINTER_TYPE:{

            auto pt = TREE_TYPE(ttype);
            if (pt) {
                tname = c_type_name(pt);
            }
            tname += "*";
            break;
        }

        default:
            tname = type_name(ttype);
            break;
        }
        return tname;
    }

    // Returns the tree node of the ultimate type that a typedef refers to
    static const_tree get_ultimate_type(const_tree ttype){

        const_tree ut = ttype;

        while(typedef_variant_p(ut)){
            auto tname = TYPE_NAME(ut);
            ut = DECL_ORIGINAL_TYPE(tname);
        }

        return ut;
    }

    static const char *tree_code_str(enum tree_code tc){
        return TREE_CODE_CLASS_STRING(TREE_CODE_CLASS(tc));
    }

    static const_tree get_pointee(const_tree ttype){
        if (TREE_CODE(ttype) == POINTER_TYPE)
            return get_ultimate_type(TREE_TYPE(ttype));
        else
            return NULL_TREE;
    }

    static bool get_fn_attr_value(const_tree fn, long& attr_value){
        bool rv = false;

        auto ref_attr = lookup_attribute(REF_ATTR_NAME, DECL_ATTRIBUTES(fn));
        if (ref_attr){
            ref_attr = TREE_VALUE(TREE_VALUE(ref_attr));
            rv = (TREE_CODE(ref_attr) == INTEGER_CST);
            if (rv)
                attr_value = int_cst_value(ref_attr);
        }
        return rv;
    }

    static bool is_heap_function(const_tree fn){
        bool rv = false;
        long attr_value = 0;

        if (get_fn_attr_value(fn, attr_value) && (attr_value & REFTRACK_HEAP_FN_FLAG)){
            rv = true;
            LOG(TRACE, function_name(fn), int(attr_value), ":heap function");
        }

        return rv;
    }

    // Returns ref_info if the tree type is a pointer to one of the structs with ref attribute
    static const ref_info* is_tracked_struct(const_tree ttype){
        const ref_info *refinfo = nullptr;
        auto pointee = get_pointee(ttype);

        if (pointee){
            auto it = G.ref_structs.find(pointee);
            if (it != G.ref_structs.cend())
                refinfo = &(it->second);
        }

        return refinfo;
    }

    static string symbol_info(tree s){
        std::stringstream rv;
        string result;
        if (s){
            rv << '[';
            try{
                rv << symbol_name(s);
                rv << ':';
                string category;

                if (VAR_P(s)){
                    category = 'V';
                }
                if (DECL_P(s)){
                    category += 'D';
                }
                if (TYPE_P(s)){
                    category += 'T';
                }
                if (FUNC_OR_METHOD_TYPE_P(s)){
                    category += 'F';
                }
                if (EXPR_P(s)){
                    category += 'E';
                }

                rv << category;
                rv << ':' << type_name(TREE_TYPE(s));

                rv << (is_generated(s) ? ",G" : "");
                rv << (TREE_USED(s) ? ",USED" : "");
                rv << (DECL_READ_P(s) ? ",READ" : "");
                rv << (is_array_elem(s) ? ",[]" : "");
                rv << (is_component(s) ? ",." : "" );
                rv << (is_tracked_struct(TREE_TYPE(s)) ? ",T" : "");
                rv << ",#B:" <<  (BLOCK_NUMBER(s));
                rv << (is_gimple_val(s) ? ",GIMPLE:V":"");
                rv << (is_gimple_lvalue(s) ? ",GIMPLE:LHS" : "");

                if (VAR_P(s)){

                    if (SSA_NAME_VAR(s)){
                        rv << ",SSA:" << symbol_name(SSA_NAME_VAR(s));
                    }
                    auto fc = get_ultimate_context(s);
                    rv << ",CTX:" << symbol_name(fc);
                }

            }
            catch(std::exception& e){
                rv << " Exception:" << e.what();
            }
            rv << ']';
        }
        rv >> result;
        return result;
    }

    // Returns true if the type of a variable v is of T *v[n] where T is a tracked type
    bool is_array_of_tracked_struct(const_tree var_type){
        return TREE_CODE(var_type) == ARRAY_TYPE && is_tracked_struct(TREE_TYPE(var_type));
    }

    // returns true if the tree type is a pointer to one of the structs with refcount field
    static bool is_pointer_to(const_tree ttype, const_tree target_type, int cvqual){
        bool rv = false;

        if (TREE_CODE(ttype) == POINTER_TYPE){
            auto pointee = TREE_TYPE(ttype);
            if (pointee == target_type)
                rv = true;
            if (cvqual)
                rv = (TYPE_QUALS(pointee) & cvqual) != 0;
        }
        return rv;
    }

    // DFS traversal of all blocks starting from the given block
    ////////////////////////////////////////////////////////////
    static void for_each_block(tree block, tree parent,
                        std::function<void(tree block, tree pblock)> visitor){
        visitor(block, parent);

        for (auto subblock = BLOCK_SUBBLOCKS(block); subblock;
             subblock = BLOCK_CHAIN(subblock)){
            LOG(TRACE,  "Subblock:");

            for_each_block(subblock, block, visitor);
        }

        auto next_block = BLOCK_CHAIN(block);
        if (next_block){
            LOG(TRACE,  "block:");
            for_each_block(next_block, parent, visitor);
        }
    }

    ////////////////////////////////////////////////////////////
    static void for_each_block_var(tree block, std::function<void(tree var)> visitor){
        for (auto block_var = BLOCK_VARS(block); block_var;
             block_var = TREE_CHAIN(block_var)) {
            visitor(block_var);
        }
    }

    static int process_block_vars(tree block){
        LOG(TRACE, "\nBlock variables:{");
        auto var_count = 0;

        auto var_visitor = [&](auto block_var){
            LOG(TRACE,  symbol_name(block_var), ':', c_type_name(TREE_TYPE(block_var)), ' ');
            var_count++;
        };

        for_each_block_var(block, var_visitor);

        LOG(TRACE,  var_count, "}");
        return var_count;
    }

    /*
     * Builds a sequence of call statements.
     * Expected: {(function, arg1), ...}
     */
    static gimple_seq build_refcall_block(const vector<gimple_build_info>& tracked_args, tree block=nullptr){
        gimple_seq gseq = nullptr;

        for(const auto& entry : tracked_args){

            auto loc = entry.loc;
            switch(entry.gcode){

            case GIMPLE_CALL:
            {
                auto var = entry.var;
                if (entry.use_tmp){

                    auto tmp_var = create_tmp_var(entry.tmp_type, REFTRACK_TMP_PREFIX);
                    auto tmp_assign = gimple_build_assign(tmp_var, var);

                    gimple_set_location(tmp_assign, loc ? loc : UNKNOWN_LOCATION);
                    if (block) {
                        gimple_set_block(tmp_assign, block);
                    }
                    gimple_seq_add_stmt(&gseq, tmp_assign);

                    var = tmp_var;
                    LOG(TRACE, "Temporary:", symbol_info(tmp_var));
                }
                auto call = gimple_build_call(entry.fn, 1, var);

                gimple_set_location(call, loc ? loc : UNKNOWN_LOCATION);
                if (block) gimple_set_block(call, block);
                update_stmt(call);
                LOG(TRACE, "Adding refcall at", ((loc ? LOCATION_LINE(loc) : -1)), symbol_info(entry.var));

                gimple_seq_add_stmt(&gseq, call);
            }
            break;

            default:
                break;
            }
        }
        return gseq;

    }

    ////////////////////////////////////////////////////////////
    static bool is_valid_destructor_fn(const_tree fn){

        if (TREE_CODE(fn) != FUNCTION_DECL){
            LOG(TRACE, "Not a function");
            return false;
        }

        // return type must be void
        auto fn_result = TREE_TYPE(fn);

        if (!VOID_TYPE_P(TREE_TYPE(fn_result))){
            LOG(TRACE, "Not void return type");
            return false;
        }

        auto param_count = 0;
        auto fnp = DECL_ARGUMENTS(fn);

        for(; fnp; fnp = DECL_CHAIN(fnp)) param_count++;

        if (param_count != 1){
            LOG(TRACE, "params != 1", param_count);
            return false;
        }

        fnp = DECL_ARGUMENTS(fn);

        return is_tracked_struct(TREE_TYPE(fnp)) != nullptr;

    }

    ////////////////////////////////////////////////////////////
    static bool is_valid_default_ref_fn(const_tree fn){
        if (TREE_CODE(fn) != FUNCTION_DECL)
            return false;

        auto param_count = 0, valid_param = 0;

        for (auto fnp = DECL_ARGUMENTS(fn); fnp; fnp = DECL_CHAIN(fnp)) {
            param_count++;
            if (is_pointer_to(TREE_TYPE(fnp), void_type_node, TYPE_QUAL_CONST))
                valid_param++;
            else
                LOG(TRACE, c_type_name(TREE_TYPE(fnp)), "!=", c_type_name(void_type_node));

        }

        auto fn_result = TREE_TYPE(fn);

        if (!VOID_TYPE_P(TREE_TYPE(fn_result))){
            return false;
        }

        return param_count == 1 && valid_param == 1;
    }

    ////////////////////////////////////////////////////////////
    static bool is_valid_ref_fn(const_tree fn, const_tree target_type){
        if (TREE_CODE(fn) != FUNCTION_DECL)
            return false;

        auto param_count = 0, valid_param = 0;

        for (auto fnp = DECL_ARGUMENTS(fn); fnp; fnp = DECL_CHAIN(fnp)) {
            param_count++;
            if (is_pointer_to(TREE_TYPE(fnp), target_type, TYPE_QUAL_CONST))
                valid_param++;
            else
                LOG(TRACE, c_type_name(TREE_TYPE(fnp)), "!=", c_type_name(target_type));

        }

        auto fn_result = TREE_TYPE(fn);

        if (!VOID_TYPE_P(TREE_TYPE(fn_result))){
            return false;
        }

        return param_count == 1 && valid_param == 1;
    }

    ////////////////////////////////////////////////////////////
    static void capture_given_fn(tree fun){
        if (fun) {
            auto fun_name = get_name(fun);
            // TODO check function signature for alloc, free

            if (G.reftrack_alloc_fn_name == fun_name){
                G.reftrack_alloc_fn = fun;
                G.orig_alloc_fn = G.get_tree(G.orig_alloc_fn_name);
                LOG(DEBUG, "Alloc functions:", get_name(G.reftrack_alloc_fn),
                        get_name(G.orig_alloc_fn));
            }
            else if (G.reftrack_free_fn_name == fun_name){
                G.reftrack_free_fn = fun;
                G.orig_free_fn = G.get_tree(G.orig_free_fn_name);
                LOG(DEBUG, "Free functions:", get_name(G.reftrack_free_fn),
                        get_name(G.orig_free_fn));
            }
            else if (G.default_addref_fn_name == fun_name){
                if (is_valid_default_ref_fn(fun)){
                    G.default_addref_fn = fun;
                    LOG(DEBUG, "Given default addref function:", fun_name);
                }
                else{
                    error("Invalid default addref function");
                }
            }
            else if (G.default_removeref_fn_name == fun_name){
                if (is_valid_default_ref_fn(fun)){
                    G.default_removeref_fn = fun;
                    LOG(DEBUG, "Given default removeref function:", fun_name);
                }
                else{
                    error("Invalid default removeref function");
                }
            }

        }
    }

    ////////////////////////////////////////////////////////////
    static void check_fn_attributes(tree fn){
        long attr_value = 0;
        if (get_fn_attr_value(fn, attr_value) && (attr_value & REFTRACK_DESTRUCTOR_FN_FLAG)){
            if (!is_valid_destructor_fn(fn))
                error("Invalid destructor function");
            else{
                G.destructor_fns.insert(fn);
            }
        }
    }

    ////////////////////////////////////////////////////////////
    static void pre_genericize_fn_cb(void *gcc_data, void *user_data) {

        tree fun = static_cast<tree>(gcc_data);
        if (fun){
            capture_given_fn(fun);
            check_fn_attributes(fun);
        }

    }

    ////////////////////////////////////////////////////////////
    static void gcc_finish_cb(void *gcc_data, void *user_data) {

        for (const auto &e : G.fn_list) {
            LOG(TRACE, e);
        }
        LOG(TRACE,  "#pass:", G.pass);
    }

    ////////////////////////////////////////////////////////////
    static void collect_struct_with_rc(tree t){

        if (!TREE_CODE(t))
            return;

        if (G.debug){
            LOG(TRACE, "struct:", type_name(t));
        }

        for (auto field = TYPE_FIELDS(t); field; field = TREE_CHAIN(field)){

            if (G.refcount_fields.find(field) != G.refcount_fields.end()){

                if (G.debug){
                    LOG(DEBUG,  c_type_name(t), "->", symbol_name(field));
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////
    static void gcc_parse_type_cb(void *gcc_data, void *user_data) {

        auto t = static_cast<tree>(gcc_data);

        if (!TREE_CODE(t))
            return;

        collect_struct_with_rc(t);

        if (G.debug){
            LOG(DEBUG,  "Parse type :", c_type_name(t), " : {");

            for (auto field = TYPE_FIELDS(t); field; field = TREE_CHAIN(field)){
                LOG(DEBUG, symbol_name(field), ':', c_type_name(TREE_TYPE(field))," @[");
                for(auto fa = DECL_ATTRIBUTES(field); fa; fa = TREE_CHAIN(fa)){
                    LOG(DEBUG, attr_name(fa), ' ');
                }
                LOG(DEBUG, "] ");

            }

            LOG(DEBUG, '}');
        }

    }

    static void gcc_early_gimple_cb(void *gcc_data, void *user_data) {

        auto cp = current_pass;
        auto tp = (tree) (gcc_data);
        if (tp) {
            LOG(DEBUG, "Tree type:",TREE_TYPE(tp),',', TREE_CODE(tp));

        }
        LOG(DEBUG, "Early gimple:", (cp ? cp->name : "<null>"));

    }

    static void gcc_pass_cb(void *gcc_data, void *user_data) {

        auto p = current_pass;
        auto gp = (struct Globals *) (user_data);
        gp->pass++;

        if (p) {
            LOG(DEBUG, "Pass:", p->name,", type:",  p->type);
        }

    }


    ////////////////////////////////////////////////////////////
    static tree function_param(tree fn, unsigned arg_index){
        auto param = NULL_TREE;
        unsigned i = 0;

        if (TREE_CODE(fn) != FUNCTION_DECL)
            return param;

        for (auto fnp = DECL_ARGUMENTS(fn); fnp; fnp = DECL_CHAIN(fnp)){
            if (i++ == arg_index){
                param = fnp;
                break;
            }
        }
        return param;
    }

    ////////////////////////////////////////////////////////////
    static tree handle_refcount_attribute(tree *node, tree name, tree args,
                                          int flags, bool *no_add_attrs){

        const auto& tcode = TREE_CODE(*node);

        vector<tree> attr_args;
        for(; args; args = TREE_CHAIN(args)){
            attr_args.push_back(TREE_VALUE(args));
        }

        switch(tcode){
        case RECORD_TYPE:
        case UNION_TYPE:
        {
            if (attr_args.size() == 0){
                const auto& afn = G.get_default_addref_fn();
                const auto& rfn = G.get_default_removeref_fn();

                if (afn == nullptr || rfn == nullptr)
                    error("Default addref/removeref functions not defined");
                else {
                    G.ref_structs[*node] = {afn, rfn, build_pointer_type(*node)};
                    if (G.debug){
                        LOG(INFO, "Tracking struct", c_type_name(*node), "using", function_name(afn), ",",
                                function_name(rfn));
                    }
                }
            }
            else if (attr_args.size() == 2){

                const auto& fn1 = attr_args[0];
                const auto& fn2 = attr_args[1];

                if (!is_valid_ref_fn(fn1, *node)
                    || !is_valid_ref_fn(fn2, *node)){
                    error("Invalid attribute arguments");
                }
                else{

                    G.ref_structs[*node] = {fn1, fn2, build_pointer_type(*node)};

                    G.ignored_fns.insert(fn1);
                    G.ignored_fns.insert(fn2);

                    if (G.debug){

                        LOG(INFO, "Tracking struct",
                                c_type_name(*node), "using",
                                function_name(fn1), ",",  function_name(fn2));

                    }
                }
            }
            else{
                error("struct requires 0 or 2 attribute arguments");
            }

        }
        break;
        case FUNCTION_DECL:
        {

            if (attr_args.size() != 1 || TREE_CODE(attr_args[0]) != INTEGER_CST)
                error("function requires a single attribute argument");

            auto arg_value = int_cst_value(attr_args[0]);

            switch(arg_value){
                /*
                 * If attribute argument value is REFTRACK_IGNORE_FLAG, then the body of function and
                 * calls to the function are NOT tracked, _but_ the return value from the function
                 * is still tracked if the type of the return value is a tracked type
                 *
                 */
            case REFTRACK_IGNORE_FLAG:

                G.ignored_fns.insert(*node);
                LOG(WARN, "Ignoring function:", get_name(*node));
                break;

            default:
                break;
            }

        }
        break;
        default:
            error("attribute can be applied only to structs/functions");
            break;
        }

        return NULL_TREE;
    }

    static struct attribute_spec refcount_attr = {
        REF_ATTR_NAME, 0, 2, false, false, false, false, handle_refcount_attribute, NULL
    };

    static void register_attributes(void *event_data, void *data){
        register_attribute(&refcount_attr);
    }

    ////////////////////////////////////////////////////////////
    static bool skip_function(tree fn){
        return is_ignored_function(fn);
    }
    ////////////////////////////////////////////////////////////
    static bool is_destructor(tree fn){
        return G.destructor_fns.find(fn) != G.destructor_fns.cend();
    }
    ////////////////////////////////////////////////////////////
    static void traverse_dfs_gimple(gimple_seq gs, std::function<bool(gimple_stmt_iterator&)> visitor){
        for (gimple_stmt_iterator gsi = gsi_start(gs); !gsi_end_p(gsi); gsi_next(&gsi)){
            auto stmt = gsi_stmt(gsi);
            auto gcode = gimple_code(stmt);

            switch(gcode){
            case GIMPLE_BIND:{
                auto gbp = dyn_cast<gbind*>(stmt);
                traverse_dfs_gimple(gimple_bind_body(gbp), visitor);
            }
                break;
            case GIMPLE_TRY:{
                auto gtp = dyn_cast<gtry*>(stmt);
                traverse_dfs_gimple(gimple_try_eval(gtp), visitor);
                traverse_dfs_gimple(gimple_try_cleanup(gtp), visitor);
            }
                break;
            default:
                break;
            }
            // TODO check return value of visitor and abort traversal
            visitor(gsi);
        }
    }

    ////////////////////////////////////////////////////////////
    inline static const char* gimple_type_str(gimple_seq gs){
        return gimple_code_name[gimple_code(gs)];
    }

    ////////////////////////////////////////////////////////////
    // Wrap the body of the gimple bind with a try finally block
    //
    ////////////////////////////////////////////////////////////
    gimple_seq gbind_with_cleanup(gbind *gbind_stmt, gimple_seq cleanup_seq){

        auto bind_body = gimple_bind_body(gbind_stmt);

        gimple_seq try_stmt = gimple_build_try(bind_body, cleanup_seq, GIMPLE_TRY_FINALLY);
        gimple_bind_set_body(gbind_stmt, try_stmt);
        return gbind_stmt;
    }

    ////////////////////////////////////////////////////////////
    struct reftrack_pass : gimple_opt_pass {

        reftrack_pass(gcc::context *ctx):gimple_opt_pass(reftrack_data, ctx) {
        }

        int instrument_gseq(function *);

        int handle_gimple_bind(function *, gimple_stmt_iterator&, gimple_seq);
        int handle_gimple_call(function *, gimple_stmt_iterator&, gimple_seq);
        int handle_gimple_assign(function *, gimple_stmt_iterator&, gimple_seq);
        int handle_gimple_return(function *, gimple_stmt_iterator&, gimple_seq);
        int transform_assign(tree, tree, gimple_stmt_iterator&);

        virtual unsigned int execute(function *fn) override{
            instrument_gseq(fn);
            return 0;
        }

        virtual reftrack_pass *clone() override {
            return this;
        }

        // tracks function variables and their last assigned value in a BB
        unordered_map<tree, tree> bb_assigned;

        unordered_set<const_tree> param_set;

        // tracks variables that are initialized in any BB
        unordered_set<const_tree> initialized;

        function *cur_fn;

        void cleanup_fn(){
            bb_assigned.clear();
            param_set.clear();
        }

        void init(function *fn){
            cleanup_fn();

            cur_fn = fn;

            for (auto param = DECL_ARGUMENTS(fn->decl); param; param = DECL_CHAIN(param)) {

                if (is_tracked_struct(TREE_TYPE(param))){
                    param_set.insert(param);
                    initialized.insert(param);
                }
            }

        }

        void bb_cleanup(basic_block bb){
            // empty
        }

        void bb_start_handler(basic_block bb){
            bb_cleanup(bb);
            // clear all assignments made in the BB.
            bb_assigned.clear();

        }

        void bb_end_handler(basic_block bb){
            // empty
        }

        bool is_param(const_tree p){ return param_set.find(p) != param_set.cend();}

        // Returns true if the given variable/field is local, or reachable from
        // a local variable or one of the parameters.

        bool is_local_var(tree var){
            bool rv = false;
            auto tcode = TREE_CODE(var);

            if (tcode == ARRAY_REF){
                return is_local_var(get_base_address(var));
            }

            if (DECL_CONTEXT(var) == cur_fn->decl){

                rv = true;
            }
            return rv;

        }

        bool is_initialized(const_tree var){
            return initialized.find(var) != initialized.cend();
        }

        // TODO handle variable of nested functions & extern/static global variables

        bool is_assigned(tree var){

            return bb_assigned.find(var) != bb_assigned.cend()
                || param_set.find(var) != param_set.cend()
                || is_initialized(var);
        }

        tree last_assigned_value(tree var){

            tree val = nullptr;

            /*
             * we consider parameters to be assigned as they are bound to arguments during
             * function invocation even though we won't know whether the argument is null or not.
             */
            if (param_set.find(var) != param_set.cend()
                && bb_assigned.find(var) == bb_assigned.cend()){
                val = var;
            }
            else {
                val = bb_assigned[var];
            }
            return val;
        }

        bool emit_removeref_p(tree var){
            bool rv = is_static(var);

            if (!rv)
                rv = !is_local_var(var);

            if (!rv && is_assigned(var)){
                if (last_assigned_value(var))
                    rv = !null_value(last_assigned_value(var));
                else
                    rv = is_initialized(var);
            }

            return rv;
        }

        void add_assignment(tree var, tree rhs){

            LOG(TRACE, symbol_name(var),"=", symbol_name(rhs));
            bb_assigned[var] = rhs;
            initialized.insert(var);
        }

        ////////////////////////////////////////////////////////////
        gimple_seq gen_local_var_cleanup(function *fn, location_t loc){
            gimple_seq rv = nullptr;
            vector<gimple_build_info> cleanup_list;

            for(auto it = bb_assigned.cbegin(); it != bb_assigned.cend(); ++it){
                const auto& var = it->first;

                if (is_static(var) || is_generated(var)){
                    continue;
                }

                const auto& refinfo = is_tracked_struct(TREE_TYPE(var));
                if (refinfo){

                    // TODO if last assignment was null, skip it
                    cleanup_list.push_back({GIMPLE_CALL, loc, refinfo->ref_remove_fn, var});
                }
            }

            if (cleanup_list.size()){
                    rv = build_refcall_block(cleanup_list);
            }

            return rv;

        }

    };


    ////////////////////////////////////////////////////////////
    int reftrack_pass::handle_gimple_bind(function *fn, gimple_stmt_iterator& gsi, gimple_seq stmt){

        LOG(TRACE, "Gimple bind");
        auto vars  = gimple_bind_vars(dyn_cast<gbind*>(stmt));

        for(; vars; vars = TREE_CHAIN(vars)){
            LOG(TRACE, gimple_loc_str(stmt),"Symbol:[", symbol_name(vars),"] ", c_type_name(TREE_TYPE(vars)));
        }

        return 0;
    }
    ////////////////////////////////////////////////////////////
    int reftrack_pass::handle_gimple_return(function *fn, gimple_stmt_iterator& gsi, gimple_seq stmt){

        const auto& gseq = gen_local_var_cleanup(fn, gimple_location(stmt));
        if (gseq)
            gsi_insert_seq_before(&gsi, gseq, GSI_SAME_STMT);

        return 0;
    }

    /* Transforms the GIMPLE assign of form A=B+C+D where atmost 2 are pointers to the
     * the same tracked type.
     * The parameter gsi should be pointing to the GIMPLE assign
     * A=B+C+D
     * is transformed into
     *
     * T=B+C+D
     * addref(T)
     * removeref(A)
     * A=T
     *
     */
    ////////////////////////////////////////////////////////////
    int reftrack_pass::transform_assign(tree addref_fn, tree removeref_fn,
                                        gimple_stmt_iterator& gsi){
        vector<gimple_build_info> tracked_assign;
        gimple_seq stmt = gsi_stmt(gsi);
        tree lhs = gimple_assign_lhs(stmt);
        tree rhs1 = gimple_assign_rhs1(stmt);
        tree rhs2 = gimple_assign_rhs2(stmt);
        tree rhs3 = gimple_assign_rhs3(stmt);
        auto lineno = gimple_location(stmt);
        auto lhs_refinfo = is_tracked_struct(TREE_TYPE(lhs));

        if (EXPR_P(lhs)){
            auto old_lhs = lhs;
            lhs = force_gimple_operand_gsi(&gsi, lhs, true, nullptr, true, GSI_SAME_STMT);
            LOG(TRACE, "Unfold LHS", gimple_loc_str(stmt), symbol_name(old_lhs), symbol_name(lhs));
        }


        if (!null_value(rhs1) && (rhs2 || rhs3)){
            auto tmp_var = create_tmp_var(lhs_refinfo->pointer_type, REFTRACK_TMP_PREFIX);

            gimple_assign_set_lhs(stmt, tmp_var); // T=B+C+D
            update_stmt(stmt);
            if (addref_fn)
                tracked_assign.push_back({GIMPLE_CALL, lineno, addref_fn, tmp_var, false,
                        lhs_refinfo->pointer_type}); // addref(T)

            if (removeref_fn){ // removeref(A)
                tracked_assign.push_back({GIMPLE_CALL, lineno, removeref_fn, lhs, false,
                    lhs_refinfo->pointer_type});
            }
            auto new_stmts = build_refcall_block(tracked_assign, gimple_block(stmt)); // {addref(T), removeref(A)*}
            auto new_assign = gimple_build_assign(lhs, tmp_var); // A=T
            gimple_seq_add_stmt(&new_stmts, new_assign);
            gsi_insert_seq_after(&gsi, new_stmts, GSI_CONTINUE_LINKING);
            LOG(TRACE, "Transform A=B+C+D for", gimple_loc_str(stmt), symbol_name(lhs));
        }
        else{

            if (!null_value(rhs1) && addref_fn)
                tracked_assign.push_back({GIMPLE_CALL, lineno, addref_fn, rhs1, EXPR_P(rhs1),
                        lhs_refinfo->pointer_type});

            if (removeref_fn){
                tracked_assign.push_back({GIMPLE_CALL, lineno, removeref_fn, lhs, false,
                        lhs_refinfo->pointer_type});
            }
            auto new_stmts = build_refcall_block(tracked_assign, gimple_block(stmt));
            gsi_insert_seq_before(&gsi, new_stmts, GSI_SAME_STMT);

        }
        return 1;
    }
    ////////////////////////////////////////////////////////////
    int reftrack_pass::handle_gimple_assign(function *fn, gimple_stmt_iterator& gsi, gimple_seq stmt){

        auto loc = gimple_loc_str(stmt);
        tree rhs1 = gimple_assign_rhs1(stmt);
        tree rhs2 = gimple_assign_rhs2(stmt);
        tree rhs3 = gimple_assign_rhs3(stmt);
        tree lhs = gimple_assign_lhs(stmt);

        if (lhs == rhs1){
            return 0;
        }

        auto lhs_arginfo = is_tracked_struct(TREE_TYPE(lhs));

        if (!lhs_arginfo) {
            LOG(TRACE, loc, "Skip", symbol_info(lhs));
            return 0;
        }

        LOG(TRACE, loc, "LHS:", symbol_info(lhs));

        if (is_generated(lhs)
            && !is_component(lhs)
            && !EXPR_P(lhs)){ // case A.2/A.3
            LOG(TRACE, loc, "A.2/A.3", symbol_info(lhs));
            return 0;
        }

        if (is_array_elem(lhs)){
            LOG(INFO, loc, "array types are not supported");
            return 0;
        }

        vector<gimple_build_info> tracked_assign;

        tree rhs = is_tracked_struct(TREE_TYPE(rhs1)) ?
            rhs1 : (rhs2 && is_tracked_struct(TREE_TYPE(rhs2))
                    ? rhs2 : rhs3 && is_tracked_struct(TREE_TYPE(rhs3)) ? rhs3 : rhs1 );

        tree addref_fn = nullptr, removeref_fn = nullptr;
        if (!null_value(rhs)){
            auto rhs_arginfo = is_tracked_struct(TREE_TYPE(rhs));

            LOG(TRACE, loc, "RHS:", "Code:", tree_code_str(gimple_assign_rhs_code(stmt)),
                    symbol_info(rhs), symbol_info(rhs2), symbol_info(rhs3));

            if (rhs_arginfo){
                addref_fn = rhs_arginfo->ref_add_fn;
            }
            else if (!rhs_arginfo){ // assignment from typecast
                addref_fn = lhs_arginfo->ref_add_fn;

            }
        }

        if (emit_removeref_p(lhs)){
            removeref_fn = lhs_arginfo->ref_remove_fn;
        }

        add_assignment(lhs, rhs);

        if (addref_fn || removeref_fn){
            transform_assign(addref_fn, removeref_fn, gsi);
        }
        return 1;
    }

    ////////////////////////////////////////////////////////////
    int reftrack_pass::handle_gimple_call(function *fn, gimple_stmt_iterator& gsi, gimple_seq stmt){
        auto loc_str = gimple_loc_str(stmt);
        auto callee = gimple_call_fndecl(stmt);

        if (!callee){
            LOG(TRACE, "Callee is null", function_name(fn), ":", gimple_loc_str(stmt));
            return 1;
        }

        location_t loc = gimple_location(stmt);
        LOG(TRACE, "call_fn:", callee, symbol_info(callee));

        vector<gimple_build_info> tracked_args, call_lhs_epilog_args;

        auto arg_count = gimple_call_num_args(stmt);

        gcall *call = dyn_cast<gcall*>(stmt);

        auto call_lhs = gimple_call_lhs(call);
        const ref_info *lhs_arginfo =  call_lhs ? is_tracked_struct(TREE_TYPE(call_lhs)) : nullptr;


        if (!skip_function(callee) && !is_destructor(callee)){
            LOG(TRACE, symbol_name(callee),
                    "#arg:",
                    (size_t)(arg_count));

            for(unsigned ai = 0; ai < arg_count; ai++) {

                auto arg = gimple_call_arg(stmt, ai);

                auto arg_refinfo = is_tracked_struct(TREE_TYPE(arg));
                auto fn_param = function_param(callee, ai);
                if (arg_refinfo && fn_param){

                    auto param_refinfo = is_tracked_struct(
                        TREE_TYPE(fn_param));

                    // we don't skip even if arg is generated as the callee
                    // would decrement the refcount always.

                    if (arg_refinfo == param_refinfo)
                        tracked_args.push_back({GIMPLE_CALL, loc, arg_refinfo->ref_add_fn, arg, EXPR_P(arg),
                            arg_refinfo->pointer_type});
                }

            }

        }


        LOG(TRACE, loc_str, symbol_info(call_lhs));

        if (call_lhs && is_heap_function(callee) && is_call_arg(call_lhs, call))
            return 0;

        if (lhs_arginfo &&
            (!is_generated(call_lhs)
             || (is_generated(call_lhs) && is_component(call_lhs) ))){

            LOG(TRACE, "CALL LHS:", symbol_info(call_lhs));

            if (emit_removeref_p(call_lhs)){
                tracked_args.push_back({GIMPLE_CALL, loc,lhs_arginfo->ref_remove_fn, call_lhs,
                        EXPR_P(call_lhs), lhs_arginfo->pointer_type});
            }
            call_lhs_epilog_args.push_back({GIMPLE_CALL, loc, lhs_arginfo->ref_add_fn, call_lhs,
                    EXPR_P(call_lhs), lhs_arginfo->pointer_type});

        }

        if (tracked_args.size()){
            auto gseq = build_refcall_block(tracked_args, gimple_block(stmt));
                gsi_insert_seq_before(&gsi, gseq, GSI_SAME_STMT);
        }
        if (call_lhs_epilog_args.size()){
            auto gseq = build_refcall_block(call_lhs_epilog_args, gimple_block(stmt));
            gsi_insert_seq_after(&gsi, gseq, GSI_NEW_STMT);
        }

        // key value doesn't matter as we track only
        // assignments of non-null values
        if (call_lhs){
            add_assignment(call_lhs, call_lhs);
        }

        return 1;
    }

    ////////////////////////////////////////////////////////////
    int reftrack_pass::instrument_gseq(function * fn)  {

        if (skip_function(fn->decl))
            return 0;

        init(fn);

        if (G.debug){
            LOG(TRACE,horiz_line,"\ninstrument_gseq():", function_name(fn->decl), "\n", horiz_line);
        }

        basic_block bb;

        gimple_stmt_iterator gsi;
        try{
            FOR_EACH_BB_FN(bb, fn){
                bb_start_handler(bb);
                LOG(TRACE, "BLOCK START");

                for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {

                    auto stmt = gsi_stmt(gsi);

                    if (gimple_clobber_p(stmt) || is_gimple_debug(stmt))
                        continue;

                    auto gcode = gimple_code(stmt);
                    LOG(TRACE, "GCODE:", gcode, gimple_type_str(stmt));
                    switch (gcode) {
                    case GIMPLE_BIND:

                        handle_gimple_bind(fn, gsi, stmt);
                        break;
                    case GIMPLE_ASSIGN:

                        handle_gimple_assign(fn, gsi, stmt);
                        break;
                    case GIMPLE_CALL:

                        // TODO handle return value of types X*

                        /* TODO gimple call might need to be processed first in order to
                         *  handle calls to identify functions like
                         *  T *id(T *x) { return x;}
                         *  T *p = T_create();
                         *  p = id(p);
                         */
                        handle_gimple_call(fn, gsi, stmt);
                        break;
                    case GIMPLE_RETURN:
                        //handle_gimple_return(fn, gsi, stmt);
                        break;
                    default:
                        break;
                    }

                }
                LOG(TRACE, "BLOCK END");
                bb_end_handler(bb);
            }
        }
        catch(std::exception& e){
            auto msg = e.what();
            LOG(ERROR,  "Exception:", (msg ? msg : "unknown"));

        }
        LOG(TRACE, horiz_line);
        return 0;
    }

    ////////////////////////////////////////////////////////////
    struct reftrack_cleanup : gimple_opt_pass {

        reftrack_cleanup(gcc::context *ctx):gimple_opt_pass(reftrack_cleanup_data, ctx) {}

        unsigned int add_block_cleanup(function *);
        unsigned int add_arg_cleanup(function *);
        unsigned int replace_mem_fun(function *);
        unsigned int add_gimple_cleanup(gbind *bind_stmt, gimple_seq cleanup_seq);

        virtual unsigned int execute(function *fn) override {
            if (G.replace_memfn)
                replace_mem_fun(fn);

            add_arg_cleanup(fn);
            add_block_cleanup(fn);

            return 0;
        }

        virtual reftrack_cleanup *clone() override {
            return this;
        }
    };

    /**
     * Generates cleanup instructions for the given variable. Recursively descends into the type and
     * generates instructions for any tracked fields.
     * Returns the number of the fields that are tracked.
     */
    int collect_tracked_fields(tree var, vector<gimple_build_info>& tracked_list){
        auto var_type = TREE_TYPE(var);
        auto refinfo = is_tracked_struct(var_type);
        int count = 0;

        if (refinfo){

            tracked_list.push_back({GIMPLE_CALL, 0, refinfo->ref_remove_fn, var, false});
            count++;
        }
        else {

            for(auto field = TYPE_FIELDS(var_type); field; field = TREE_CHAIN(field)){
                if (RECORD_OR_UNION_TYPE_P(var_type)){
                    auto mem_path = build3(COMPONENT_REF, TREE_TYPE(field), var, field, NULL_TREE);
                    count+=collect_tracked_fields(mem_path, tracked_list);
                }
            }
        }

        return count;
    }

    ////////////////////////////////////////////////////////////
    unsigned int reftrack_cleanup::replace_mem_fun(function * fn){

        if (skip_function(fn->decl))
            return 0;

        traverse_dfs_gimple(fn->gimple_body, [&](auto& gsi)->bool{

            auto stmt = gsi_stmt(gsi);

            if (gimple_code(stmt) != GIMPLE_CALL)
                return false;

            auto call = dyn_cast<gcall*>(stmt);
            auto arg_count = gimple_call_num_args(call);
            auto callee = gimple_call_fndecl(stmt);
            auto call_lhs = gimple_call_lhs(call);

            const ref_info *lhs_arginfo =  call_lhs ? is_tracked_struct(TREE_TYPE(call_lhs)) : nullptr;

            /*
             * Replace original alloc function with reftrack equivalent
             * ONLY IF lhs is a tracked type.
             */
            if (lhs_arginfo){
                tree new_callee = nullptr;

                if (callee == G.get_orig_alloc_fn()){
                    new_callee = G.get_reftrack_alloc_fn();
                    LOG(TRACE, gimple_loc_str(stmt), "replacing allocator");

                    if (new_callee){
                        gimple_call_set_fndecl(call, new_callee);
                        update_stmt(call);
                        LOG(TRACE, gimple_loc_str(stmt), "allocator replaced", get_name(new_callee));
                    }
                    else{
                        LOG(ERROR, gimple_loc_str(stmt),
                                "Replace flag given, but allocator function missing");
                    }
                }

            }

            /*
             * Replace original free function with reftrack equivalent.
             */
            if (callee == G.get_orig_free_fn()){

                for(unsigned ai = 0; ai < arg_count; ai++){
                    auto arg = gimple_call_arg(stmt, ai);
                    if (is_tracked_struct(TREE_TYPE(arg))){
                        // Assumption: at least one arg is of tracked type.
                        auto new_callee = G.get_reftrack_free_fn();

                        if (new_callee){
                            gimple_call_set_fndecl(call, new_callee);
                            update_stmt(call);
                        }
                        else{
                            LOG(ERROR, gimple_loc_str(stmt),
                                    "Replace flag given, but free function missing");
                        }
                        break;
                    }
                }
            }
            return false;

        });

        return 0;

    }
    ////////////////////////////////////////////////////////////
    unsigned int reftrack_cleanup::add_gimple_cleanup(gbind *bind_stmt,
                                                      gimple_seq cleanup_seq){
        gimple_seq bind_body = gimple_bind_body(bind_stmt);
        auto try_stmt = bind_body;

        if (is_a<gtry*>(try_stmt)
            &&  gimple_try_kind(try_stmt) == GIMPLE_TRY_FINALLY){
            auto try_cleanup = gimple_try_cleanup(try_stmt);
            auto gsi = gsi_last(cleanup_seq);
            gsi_insert_seq_after(&gsi, try_cleanup, GSI_NEW_STMT);
            gimple_try_set_cleanup(dyn_cast<gtry*>(try_stmt), cleanup_seq);
            LOG(TRACE, "Reusing try block at ", gimple_loc_str(bind_stmt) );
        }
        else{
            gbind_with_cleanup(bind_stmt, cleanup_seq);
        }

        return 0;

    }
    ////////////////////////////////////////////////////////////
    unsigned int reftrack_cleanup::add_block_cleanup(function *fn){

        if (skip_function(fn->decl))
            return 0;

        traverse_dfs_gimple(fn->gimple_body, [&](auto& gsi)->bool{

            auto stmt = gsi_stmt(gsi);
            auto gcode = gimple_code(stmt);
            if (gcode != GIMPLE_BIND)
                return false;

            LOG(TRACE,horiz_line, "\ncleanup:", function_name(fn->decl),
                    "\n",horiz_line, "");

            vector<gimple_build_info> tracked_vars;
            auto bind_stmt = dyn_cast<gbind*>(stmt);

            for (auto block_var = gimple_bind_vars(bind_stmt); block_var;
                 block_var = TREE_CHAIN(block_var)) {

                LOG(TRACE, "Block var:", symbol_info(block_var));

                if (is_generated(block_var) || TREE_STATIC(block_var) )
                    continue;

                if (is_array_of_tracked_struct(TREE_TYPE(block_var))){
                    LOG(TRACE, "Array type unsupported:var:", symbol_name(block_var));
                    continue;
                }

                int count = collect_tracked_fields(block_var, tracked_vars);

                LOG(TRACE, "var traverse:",count);

            }

            if (tracked_vars.size()){

                LOG(TRACE, "\nAdded", tracked_vars.size(), "cleanup statement(s)");
                add_gimple_cleanup(bind_stmt, build_refcall_block(tracked_vars));
            }

            LOG(TRACE,horiz_line);

            return false;
        });


        return 0;

    }
    ////////////////////////////////////////////////////////////
    unsigned int reftrack_cleanup::add_arg_cleanup(function *fn) {

        if (skip_function(fn->decl) || is_destructor(fn->decl))
            return 0;

        vector<gimple_build_info> tracked_args;

        for (auto param = DECL_ARGUMENTS(fn->decl); param; param = DECL_CHAIN(param)){
            auto refinfo = is_tracked_struct(TREE_TYPE(param));
            if (refinfo){
                tracked_args.push_back({GIMPLE_CALL, UNKNOWN_LOCATION, refinfo->ref_remove_fn, param, false});
            }
        }
        if (tracked_args.size()){
            auto top_bind_stmt = gimple_build_bind(NULL_TREE, fn->gimple_body, NULL_TREE);
            gbind_with_cleanup(top_bind_stmt, build_refcall_block(tracked_args));
            fn->gimple_body = top_bind_stmt;
        }

        return 0;
    }

} // END NAMESPACE reftrack

int plugin_init(struct plugin_name_args *plugin_info,
                struct plugin_gcc_version *version)
{

    using namespace reftrack;

    int gcc_basever[] = { 12, 3 };

    int given_ver_comp[] = {0, 0};

    string given_ver = version->basever;

    auto first_pos = given_ver.find('.');
    if (first_pos != given_ver.npos){

        given_ver_comp[0] = atoi(given_ver.substr(0, first_pos).c_str());
        auto second_pos = given_ver.find('.', first_pos+1);
        if (second_pos != given_ver.npos)
            given_ver_comp[1] = atoi(given_ver.substr(first_pos+1, second_pos-first_pos).c_str());
        LOG(INFO, {"Given version:", xstring(given_ver_comp[0])+"."+ xstring(given_ver_comp[1])});
    }

    if ((given_ver_comp[0]*10+given_ver_comp[1]) < (gcc_basever[0]*10+gcc_basever[1])) {
        LOG(ERROR, {PLUGIN_NAME, ":version mismatch", "expected: >=",
                xstring(gcc_basever[0])+ "."+ xstring(gcc_basever[1]),
                ",received:", version->basever});
        return 1;
    }

    if (!lang_GNU_C()){
        LOG(ERROR, {"Unsupported source language:", lang_hooks.name});
        return 1;
    }

    for(int i = 0; i < plugin_info->argc; i++){
        string arg_key = plugin_info->argv[i].key;

        if (arg_key == "orig_alloc" ){
            G.orig_alloc_fn_name = plugin_info->argv[i].value;
            LOG(TRACE, "Given original alloc function:", G.orig_alloc_fn_name);
        }
        else if (arg_key == "alloc" ){
            G.reftrack_alloc_fn_name = plugin_info->argv[i].value;
            LOG(TRACE, "Given alloc function:", G.reftrack_alloc_fn_name);
        }
        else if (arg_key == "orig_free"){
            G.orig_free_fn_name = plugin_info->argv[i].value;
            LOG(TRACE, "Given original free function:", G.orig_free_fn_name);
        }
        else if (arg_key == "free"){
            G.reftrack_free_fn_name = plugin_info->argv[i].value;
            LOG(TRACE, "Given free function:", G.reftrack_free_fn_name);
        }
        else if (arg_key == "addref"){
            G.default_addref_fn_name = plugin_info->argv[i].value;
            LOG(TRACE, "Given default addref function:", G.default_addref_fn_name);
        }
        else if (arg_key == "removeref"){
            G.default_removeref_fn_name = plugin_info->argv[i].value;
            LOG(TRACE, "Given default removeref function:", G.default_removeref_fn_name);
        }
        else if (arg_key == "log_level"){
            G.cur_log_level = log_level(atoi(plugin_info->argv[i].value));
        }
        else if (arg_key == "replace"){
            G.replace_memfn = true;
        }
        else{
            error("Unknown plugin argument:%s", arg_key.c_str());
        }
    }

    register_callback(PLUGIN_NAME, PLUGIN_INFO, nullptr, &G.pinfo);
    register_callback(PLUGIN_NAME, PLUGIN_ATTRIBUTES, reftrack::register_attributes, NULL);


    register_callback(PLUGIN_NAME, PLUGIN_PRE_GENERICIZE,
                      pre_genericize_fn_cb, &G);

    register_callback(PLUGIN_NAME, PLUGIN_PASS_EXECUTION, gcc_pass_cb, &G);

    struct register_pass_info rpi = {
        .pass = new reftrack_pass(g),
        .reference_pass_name = "cfg",
        .ref_pass_instance_number = 1,
        .pos_op = PASS_POS_INSERT_AFTER
    };

    register_callback(PLUGIN_NAME, PLUGIN_PASS_MANAGER_SETUP, NULL,
      &rpi);

    struct register_pass_info cleanup_rpi = {
        .pass = new reftrack_cleanup(g),
        .reference_pass_name = "omplower",
        .ref_pass_instance_number = 1,
        .pos_op = PASS_POS_INSERT_AFTER
    };

    register_callback(PLUGIN_NAME, PLUGIN_PASS_MANAGER_SETUP, NULL,
                      &cleanup_rpi);

    LOG(INFO, PLUGIN_NAME, "plugin initialized");

    return 0;
}
