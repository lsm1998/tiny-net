#ifndef TINY_NET_RB_TREE_H
#define TINY_NET_RB_TREE_H

typedef enum rb_color_t
{
    RB_RED = 0,
    RB_BLACK,
} rb_color_t;

typedef struct rb_node_t
{
    struct rb_node_t* parent;
    struct rb_node_t* left;
    struct rb_node_t* right;
    rb_color_t color;
} rb_node_t;

typedef struct rb_tree_t
{
    rb_node_t* root;
} rb_tree_t;

rb_color_t rb_color(const rb_node_t* node);

void rb_tree_init(rb_tree_t* tree);

void rb_node_init(rb_node_t* node);

void rb_rotate_left(rb_tree_t* tree, rb_node_t* node);

void rb_rotate_right(rb_tree_t* tree, rb_node_t* node);

void rb_insert_fixup(rb_tree_t* tree, rb_node_t* node);

void rb_link_node(rb_tree_t* tree, rb_node_t* parent, rb_node_t** link, rb_node_t* node);

rb_node_t* rb_minimum(rb_node_t* node);

void rb_transplant(rb_tree_t* tree, const rb_node_t* old_node, rb_node_t* new_node);

void rb_erase_fixup(rb_tree_t* tree, rb_node_t* node, rb_node_t* parent);

void rb_erase(rb_tree_t* tree, rb_node_t* node);

#endif //TINY_NET_RB_TREE_H
