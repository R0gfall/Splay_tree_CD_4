#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#define NUM_OF_KEYWORDS 44
#define MAX_KEYWORD_LEN 20

char standart_c_keywords[NUM_OF_KEYWORDS][MAX_KEYWORD_LEN] = {
"_Alignas",
"_Alignof",
"_Atomic",
"_Bool",
"_Complex",
"_Generic",
"_Imaginary",
"_Noreturn",
"_Static_assert",
"_Thread_local",
"auto",
"break",
"case",
"char",
"const",
"continue",
"default",
"do",
"double",
"else",
"enum",
"extern",
"float",
"for",
"goto",
"if",
"inline",
"int",
"long",
"register",
"restrict",
"return",
"short",
"signed",
"sizeof",
"static",
"struct",
"switch",
"typedef",
"union",
"unsigned",
"void",
"volatile",
"while"
};

struct SplayTree {
	int count = 0; //Количество встреченных слов
	char keyword[MAX_KEYWORD_LEN] = ""; //Ключевое слово
	SplayTree* parent;
	SplayTree* left;
	SplayTree* right;
};

void make_string(char* keyword, char symbol, SplayTree** keyword_tree_root);
void print_tree(SplayTree* root);
SplayTree* make_balanced_tree(char standart_c_keywords[NUM_OF_KEYWORDS][MAX_KEYWORD_LEN], int left, int right);
SplayTree* search_keyword_in_tree(SplayTree* root, char* keyword);

void Splay(struct SplayTree* keyword_tree_root);

void zig_left(struct SplayTree* keyword_tree_root);
void zig_right(struct SplayTree* keyword_tree_root);
void zig_zig_left(struct SplayTree* root);
void zig_zig_right(struct SplayTree* root);
void zig_zag_left(struct SplayTree* root);
void zig_zag_right(struct SplayTree* root);

int main(int argc, char** argv) {
	SplayTree* keyword_tree_root = make_balanced_tree(standart_c_keywords, 0, NUM_OF_KEYWORDS - 1);

	keyword_tree_root->parent = NULL;

	char inp_file[55];

	if (argc > 1)
		strcpy(inp_file, argv[1]);
	else {
		//printf("Введите имя файла(test.c): ");
		//scanf("%s", inp_file);
		strcpy(inp_file, "input.cpp");
	}

	FILE* inp = fopen(inp_file, "r");

	char keyword[255] = { 0 };

	char c, prev_c = ' ';
	char single_comm = 0, multi_comm = 0, symbol = 0, str_const = 0, multi_comm_opened = 0, multi_comm_closed = 0, back_slash_count = 0;

	//Файл читается посимольно, и все символы, кроме комментариев и строковых констант поступают на вход функции make_string
	//
	//make_string добавляет символы в строку keyword, когда встречается символ-разделитель, строка сравнивается с ключевыми словами и очищается

	while (!feof(inp)) {
		c = fgetc(inp);
		if (str_const) {
			if (symbol == '"') {
				if (c == '"' && (back_slash_count % 2 == 0) || (back_slash_count % 2 == 0) && c == '\n') \
					str_const = 0;
			}
			else
				if (c == '\'' && (back_slash_count % 2 == 0) || c == '\n')
					str_const = 0;

			if (c == '\\')
				back_slash_count += 1;
			else
				back_slash_count = 0;
		}
		else {
			if (single_comm || multi_comm) {
				if (multi_comm && prev_c == '*' && c == '/' && !multi_comm_opened) {
					multi_comm = 0;
					multi_comm_closed = 1;
				}
				else
					multi_comm_opened = 0;

				if (single_comm && prev_c != '\\' && c == '\n') {
					single_comm = 0;
				}
			}
			else {
				if (c == '"' || c == '\'') {
					if (prev_c == '/' && !multi_comm_closed)
						make_string(keyword, prev_c, &keyword_tree_root);

					str_const = 1;
					back_slash_count = 0;
					symbol = c;
				}
				else {
					if (prev_c == '/' && c == '/' && !multi_comm_closed) {
						single_comm = 1;
						make_string(keyword, '\n', &keyword_tree_root);
					}
					if (prev_c == '/' && c == '*' && !multi_comm_closed) {
						multi_comm = 1;
						multi_comm_opened = 1;
						make_string(keyword, '\n', &keyword_tree_root);
					}
					if (c != '/' && c != '*') {
						if (prev_c == '/' && !multi_comm_closed)
							make_string(keyword, prev_c, &keyword_tree_root);
						make_string(keyword, c, &keyword_tree_root);

						multi_comm_closed = 0;
					}
				}
			}
		}
		prev_c = c;
	}

	make_string(keyword, c, &keyword_tree_root);
	fclose(inp);

	print_tree(keyword_tree_root);
	return 0;
}

void make_string(char* keyword, char symbol, SplayTree** keyword_tree_root) {
	char sep[] = ",;\n() {}[]	&?*-+=|/><!^~:"; //Возможные разделители(после и перед которыми могут идти ключевые слова)   //`/@"'#№$%
	if (strchr(sep, symbol) || symbol == EOF) {//Если на вход получен разделитель
		SplayTree* current_keyword = search_keyword_in_tree(*keyword_tree_root, keyword); //Поиск текущего ключевого слова в дереве
		if (current_keyword != NULL) {
			current_keyword->count++;
			while (current_keyword->parent)
				Splay(current_keyword);
			*keyword_tree_root = current_keyword;
		}

		keyword[0] = 0; //Строка очищается
	}
	else {//Иначе символ записывается в строку
		if (strlen(keyword) == MAX_KEYWORD_LEN) {//Если длина строки превышает возможную длину ключевого слова, то новые символы в нее не записываются, чтобы избежать переполнения
			return;
		}

		int i = 0;
		while (keyword[i]) i++;
		keyword[i] = symbol;
		keyword[i + 1] = 0;
	}
}

void print_tree(SplayTree* root) {
	if (root != NULL) {
		print_tree(root->left);
		if (root->count)
			printf("Количество \"%s\": %d\n", root->keyword, root->count);
		print_tree(root->right);
	}
}

SplayTree* make_balanced_tree(char standart_c_keywords[NUM_OF_KEYWORDS][MAX_KEYWORD_LEN], int left, int right) {
	if (left > right)
		return NULL;

	SplayTree* root = (SplayTree*)malloc(sizeof(SplayTree));
	memset(root, 0x00, sizeof(SplayTree));

	int middle = (left + right) / 2;
	strcpy(root->keyword, standart_c_keywords[middle]);
	root->left = make_balanced_tree(standart_c_keywords, left, middle - 1);
	root->right = make_balanced_tree(standart_c_keywords, middle + 1, right);

	if (root->left) root->left->parent = root;
	if (root->right) root->right->parent = root;

	return root;
}

SplayTree* search_keyword_in_tree(SplayTree* root, char* keyword) {
	if (root == NULL)
		return NULL;

	if (!strcmp(root->keyword, keyword))
		return root;

	if (strcmp(keyword, root->keyword) < 0)
		return search_keyword_in_tree(root->left, keyword);
	else
		return search_keyword_in_tree(root->right, keyword);
}

void Splay(struct SplayTree* keyword_tree_root) {
	if (keyword_tree_root->parent->parent == NULL)
		if (strcmp(keyword_tree_root->keyword, keyword_tree_root->parent->keyword) < 0)
			zig_left(keyword_tree_root);
		else
			zig_right(keyword_tree_root);
	else
		if ((strcmp(keyword_tree_root->keyword, keyword_tree_root->parent->keyword) < 0) && (strcmp(keyword_tree_root->parent->keyword, keyword_tree_root->parent->parent->keyword) < 0))
			zig_zig_left(keyword_tree_root);
		else
			if ((strcmp(keyword_tree_root->keyword, keyword_tree_root->parent->keyword) > 0) && (strcmp(keyword_tree_root->parent->keyword, keyword_tree_root->parent->parent->keyword) > 0))
				zig_zig_right(keyword_tree_root);
			else
				if ((strcmp(keyword_tree_root->keyword, keyword_tree_root->parent->keyword) > 0) && (strcmp(keyword_tree_root->parent->keyword, keyword_tree_root->parent->parent->keyword) < 0))
					zig_zag_left(keyword_tree_root);
				else
					if ((strcmp(keyword_tree_root->keyword, keyword_tree_root->parent->keyword) < 0) && (strcmp(keyword_tree_root->parent->keyword, keyword_tree_root->parent->parent->keyword) > 0))
						zig_zag_right(keyword_tree_root);
}


void zig_left(struct SplayTree* keyword_tree_root) {
	keyword_tree_root->parent->left = keyword_tree_root->right;
	keyword_tree_root->right = keyword_tree_root->parent;
	keyword_tree_root->parent = keyword_tree_root->right->parent;
	keyword_tree_root->right->parent = keyword_tree_root;

	if (keyword_tree_root->parent && keyword_tree_root->parent->left == keyword_tree_root->right)
		keyword_tree_root->parent->left = keyword_tree_root;
	if (keyword_tree_root->parent && keyword_tree_root->parent->right == keyword_tree_root->right)
		keyword_tree_root->parent->right = keyword_tree_root;

	if (keyword_tree_root->right->left != NULL)
		keyword_tree_root->right->left->parent = keyword_tree_root->right;
}

void zig_right(struct SplayTree* keyword_tree_root) {
	keyword_tree_root->parent->right = keyword_tree_root->left;
	keyword_tree_root->left = keyword_tree_root->parent;
	keyword_tree_root->parent = keyword_tree_root->left->parent;
	keyword_tree_root->left->parent = keyword_tree_root;

	if (keyword_tree_root->parent && keyword_tree_root->parent->left == keyword_tree_root->left)
		keyword_tree_root->parent->left = keyword_tree_root;
	if (keyword_tree_root->parent && keyword_tree_root->parent->right == keyword_tree_root->left)
		keyword_tree_root->parent->right = keyword_tree_root;

	if (keyword_tree_root->left->right != NULL)
		keyword_tree_root->left->right->parent = keyword_tree_root->left;
}

void zig_zig_left(struct SplayTree* root) {
	zig_left(root->parent);
	zig_left(root);
}
void zig_zig_right(struct SplayTree* root) {
	zig_right(root->parent);
	zig_right(root);
}
void zig_zag_left(struct SplayTree* root) {
	zig_right(root);
	zig_left(root);
}
void zig_zag_right(struct SplayTree* root) {
	zig_left(root);
	zig_right(root);
}
