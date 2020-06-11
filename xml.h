#ifndef __XML_h__
#define __XML_h__ 1

typedef struct Attribute
{
	char *name;
	char *value;
} attribute_t;

typedef struct XML_Node
{
	char *name;
	char *value;
	attribute_t *attributes;
	struct XML_Node **children; // array of node pointers
	int nr_children;
	int nr_attributes;
} xml_node_t;

typedef xml_node_t *node_ptr;

typedef struct XML_Tree
{
	xml_node_t *root;
	int nr_nodes;
} xml_tree_t;

#define XML_NODE_VALUE(n) ((n)->n_value)

/*
 * Parse XML data in file specified by PATH.
 * Return an XML tree object.
 */
//xml_tree_t *parse_xml_file(char *path);
//xml_node_t *XML_find_node(xml_tree_t *, char *);
//char *XML_node_get_value(xml_node_t *);
//void free_xml_tree(xml_tree_t *);

#endif /* !defined __XML_h__ */
