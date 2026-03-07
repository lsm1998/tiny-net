#include "rb_tree.h"
#include <stddef.h>

rb_color_t rb_color(const rb_node_t* node)
{
    return node ? node->color : RB_BLACK;
}

void rb_tree_init(rb_tree_t* tree)
{
    tree->root = NULL;
}

void rb_node_init(rb_node_t* node)
{
    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;
    node->color = RB_RED;
}

void rb_rotate_left(rb_tree_t* tree, rb_node_t* node)
{
    rb_node_t* right = node->right;
    node->right = right->left;
    if (right->left)
    {
        right->left->parent = node;
    }

    right->parent = node->parent;
    if (node->parent == NULL)
    {
        tree->root = right;
    }
    else if (node == node->parent->left)
    {
        node->parent->left = right;
    }
    else
    {
        node->parent->right = right;
    }

    right->left = node;
    node->parent = right;
}

void rb_rotate_right(rb_tree_t* tree, rb_node_t* node)
{
    rb_node_t* left = node->left;
    node->left = left->right;
    if (left->right)
    {
        left->right->parent = node;
    }

    left->parent = node->parent;
    if (node->parent == NULL)
    {
        tree->root = left;
    }
    else if (node == node->parent->right)
    {
        node->parent->right = left;
    }
    else
    {
        node->parent->left = left;
    }

    left->right = node;
    node->parent = left;
}

void rb_insert_fixup(rb_tree_t* tree, rb_node_t* node)
{
    while (node->parent && node->parent->color == RB_RED)
    {
        rb_node_t* parent = node->parent;
        rb_node_t* grand = parent->parent;

        if (parent == grand->left)
        {
            rb_node_t* uncle = grand->right;
            if (rb_color(uncle) == RB_RED)
            {
                parent->color = RB_BLACK;
                uncle->color = RB_BLACK;
                grand->color = RB_RED;
                node = grand;
            }
            else
            {
                if (node == parent->right)
                {
                    node = parent;
                    rb_rotate_left(tree, node);
                    parent = node->parent;
                    grand = parent->parent;
                }

                parent->color = RB_BLACK;
                grand->color = RB_RED;
                rb_rotate_right(tree, grand);
            }
        }
        else
        {
            rb_node_t* uncle = grand->left;
            if (rb_color(uncle) == RB_RED)
            {
                parent->color = RB_BLACK;
                uncle->color = RB_BLACK;
                grand->color = RB_RED;
                node = grand;
            }
            else
            {
                if (node == parent->left)
                {
                    node = parent;
                    rb_rotate_right(tree, node);
                    parent = node->parent;
                    grand = parent->parent;
                }

                parent->color = RB_BLACK;
                grand->color = RB_RED;
                rb_rotate_left(tree, grand);
            }
        }
    }

    if (tree->root)
    {
        tree->root->color = RB_BLACK;
    }
}

void rb_link_node(rb_tree_t* tree, rb_node_t* parent, rb_node_t** link, rb_node_t* node)
{
    node->parent = parent;
    node->left = NULL;
    node->right = NULL;
    node->color = RB_RED;
    *link = node;
    rb_insert_fixup(tree, node);
}

rb_node_t* rb_minimum(rb_node_t* node)
{
    while (node && node->left)
    {
        node = node->left;
    }
    return node;
}

void rb_transplant(rb_tree_t* tree, const rb_node_t* old_node, rb_node_t* new_node)
{
    if (old_node->parent == NULL)
    {
        tree->root = new_node;
    }
    else if (old_node == old_node->parent->left)
    {
        old_node->parent->left = new_node;
    }
    else
    {
        old_node->parent->right = new_node;
    }

    if (new_node)
    {
        new_node->parent = old_node->parent;
    }
}

void rb_erase_fixup(rb_tree_t* tree, rb_node_t* node, rb_node_t* parent)
{
    while ((node == NULL || rb_color(node) == RB_BLACK) && node != tree->root)
    {
        if (parent && node == parent->left)
        {
            rb_node_t* sibling = parent->right;
            if (rb_color(sibling) == RB_RED)
            {
                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_left(tree, parent);
                sibling = parent->right;
            }
            if (rb_color(sibling ? sibling->left : NULL) == RB_BLACK &&
                rb_color(sibling ? sibling->right : NULL) == RB_BLACK)
            {
                if (sibling)
                {
                    sibling->color = RB_RED;
                }
                node = parent;
                parent = node ? node->parent : NULL;
            }
            else
            {
                if (rb_color(sibling ? sibling->right : NULL) == RB_BLACK)
                {
                    if (sibling && sibling->left)
                    {
                        sibling->left->color = RB_BLACK;
                    }
                    if (sibling)
                    {
                        sibling->color = RB_RED;
                        rb_rotate_right(tree, sibling);
                    }
                    sibling = parent->right;
                }

                if (sibling)
                {
                    sibling->color = parent->color;
                }
                parent->color = RB_BLACK;
                if (sibling && sibling->right)
                {
                    sibling->right->color = RB_BLACK;
                }
                rb_rotate_left(tree, parent);
                node = tree->root;
                break;
            }
        }
        else
        {
            rb_node_t* sibling = parent ? parent->left : NULL;
            if (rb_color(sibling) == RB_RED)
            {
                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_right(tree, parent);
                sibling = parent->left;
            }

            if (rb_color(sibling ? sibling->left : NULL) == RB_BLACK &&
                rb_color(sibling ? sibling->right : NULL) == RB_BLACK)
            {
                if (sibling)
                {
                    sibling->color = RB_RED;
                }
                node = parent;
                parent = node ? node->parent : NULL;
            }
            else
            {
                if (rb_color(sibling ? sibling->left : NULL) == RB_BLACK)
                {
                    if (sibling && sibling->right)
                    {
                        sibling->right->color = RB_BLACK;
                    }
                    if (sibling)
                    {
                        sibling->color = RB_RED;
                        rb_rotate_left(tree, sibling);
                    }
                    sibling = parent->left;
                }

                if (sibling)
                {
                    sibling->color = parent->color;
                }
                parent->color = RB_BLACK;
                if (sibling && sibling->left)
                {
                    sibling->left->color = RB_BLACK;
                }
                rb_rotate_right(tree, parent);
                node = tree->root;
                break;
            }
        }
    }

    if (node)
    {
        node->color = RB_BLACK;
    }
}

void rb_erase(rb_tree_t* tree, rb_node_t* node)
{
    rb_node_t* child = NULL;
    rb_node_t* child_parent = NULL;
    rb_node_t* replace = node;
    rb_color_t replace_color = replace->color;

    if (node->left == NULL)
    {
        child = node->right;
        child_parent = node->parent;
        rb_transplant(tree, node, node->right);
    }
    else if (node->right == NULL)
    {
        child = node->left;
        child_parent = node->parent;
        rb_transplant(tree, node, node->left);
    }
    else
    {
        replace = rb_minimum(node->right);
        replace_color = replace->color;
        child = replace->right;

        if (replace->parent == node)
        {
            child_parent = replace;
            if (child)
            {
                child->parent = replace;
            }
        }
        else
        {
            child_parent = replace->parent;
            rb_transplant(tree, replace, replace->right);
            replace->right = node->right;
            replace->right->parent = replace;
        }

        rb_transplant(tree, node, replace);
        replace->left = node->left;
        replace->left->parent = replace;
        replace->color = node->color;
    }

    if (replace_color == RB_BLACK)
    {
        rb_erase_fixup(tree, child, child_parent);
    }

    rb_node_init(node);
}
