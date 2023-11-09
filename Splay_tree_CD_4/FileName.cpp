#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#define ULL unsigned long long

bool Flag_global = false;

struct Splay_tree_number {
	
	char number_16[100];
	ULL number_10;
	int count;
	Splay_tree_number* parent_tree;
	Splay_tree_number* left_tree;
	Splay_tree_number* right_tree;
};


ULL invert_16_to_10(char number_16[100])
{
	ULL summ = 0;
	int symbol;
	int crt_of_numbers = strlen(number_16) - 1;
	int crt = strlen(number_16);

	for (int i = 0; i < crt; i++) {
		switch (number_16[i]) {
		case '0': symbol = 0; break;
		case '1': symbol = 1; break;
		case '2': symbol = 2; break;
		case '3': symbol = 3; break;
		case '4': symbol = 4; break;
		case '5': symbol = 5; break;
		case '6': symbol = 6; break;
		case '7': symbol = 7; break;
		case '8': symbol = 8; break;
		case '9': symbol = 9; break;
		case 'A': symbol = 10; break;
		case 'B': symbol = 11; break;
		case 'C': symbol = 12; break;
		case 'D': symbol = 13; break;
		case 'E': symbol = 14; break;
		case 'F': symbol = 15; break;
		case 'a': symbol = 10; break;
		case 'b': symbol = 11; break;
		case 'c': symbol = 12; break;
		case 'd': symbol = 13; break;
		case 'e': symbol = 14; break;
		case 'f': symbol = 15; break;
		case 'U': return summ;
		default: printf("WARNINGS!\n"); break;
		}
		summ = summ + symbol * pow(16, crt_of_numbers);
		crt_of_numbers--;

	}

	return summ;

}

void zig_left(Splay_tree_number* start) {

	Splay_tree_number* start_0 = NULL;
	//printf("1");
	if (start->parent_tree->parent_tree != NULL) start_0 = start->parent_tree->parent_tree;

	start->parent_tree->left_tree = start->right_tree; //Перепревязка b дерева (правого листа от start)

	if (start->right_tree != NULL) start->right_tree->parent_tree = start->parent_tree;

	start->parent_tree->parent_tree = start; //Перепривзяка start и start-parent	
	start->right_tree = start->parent_tree; //
	start->parent_tree = start_0;

	/*printf("-%s\n", start);
	printf("-%s\n", start->left_tree);
	printf("-%s\n", start->right_tree);
	printf("-%s\n", start->parent_tree);*/
	
}

void giz_right(Splay_tree_number* start) {

	//printf("2");
	//start->parent_tree->right_tree = start->left_tree;//
	//start->left_tree = start->parent_tree;
	//start->parent_tree = NULL;
	//start->left_tree->parent_tree = start;

	//if (start->left_tree->right_tree != NULL) start->left_tree->right_tree->parent_tree = start->left_tree;

	Splay_tree_number* start_0 = NULL;

	if (start->parent_tree->parent_tree != NULL) start_0 = start->parent_tree->parent_tree;

	start->parent_tree->right_tree = start->left_tree;

	if (start->left_tree != NULL) start->left_tree->parent_tree = start->parent_tree;//
	start->parent_tree->parent_tree = start;
	start->left_tree = start->parent_tree;
	start->parent_tree = start_0;

	/*printf("--%s\n", start);
	printf("--%s\n", start->left_tree);
	printf("--%s\n", start->right_tree);
	printf("--%s\n", start->parent_tree);*/
}

void zig_zig_left(Splay_tree_number* start) {

	zig_left(start->parent_tree);
	zig_left(start);
}

void giz_giz_right(Splay_tree_number* start){

	
	giz_right(start->parent_tree);
	giz_right(start);
	

}

void zig_zag_left(Splay_tree_number* start) {

	giz_right(start);
	zig_left(start);
}

void giz_gaz_right(Splay_tree_number* start) {

	zig_left(start);
	giz_right(start);
}

void splay_tree_func(Splay_tree_number* start) {

	while (start->parent_tree != NULL) {
		if (start->parent_tree->parent_tree == NULL) {
			if ((start->parent_tree->number_10) > (start->number_10)) {
				
				zig_left(start);

				return;
			}
			else {
				
				giz_right(start);
				return;
			}
		}
		else {
			if ((start->parent_tree->number_10 > start->number_10) && (start->parent_tree->parent_tree->number_10 > start->parent_tree->number_10)) {
				zig_zig_left(start);
			}
			else if ((start->parent_tree->number_10 < start->number_10) && (start->parent_tree->parent_tree->number_10 < start->parent_tree->number_10)) {
				giz_giz_right(start);
				
			}
			else if ((start->parent_tree->number_10 < start->number_10) && (start->parent_tree->parent_tree->number_10 > start->parent_tree->number_10)) {
				zig_zag_left(start);
			}
			else {
				giz_gaz_right(start);
			}
		}

	}
}

Splay_tree_number* search_least(Splay_tree_number* start, ULL number_10)
{
	//printf("!%d\n", start->number_10);
	while ((start)) {
		
		if (start->number_10 == number_10) {
			start->count++;
			Flag_global = true;
			
			return start;
		}
		if (((start->left_tree == NULL) && (start->number_10 > number_10)) || ((start->right_tree == NULL) && (start->number_10 < number_10))) {
			Flag_global = false;
			//printf("_1\n");
			return start;
		}

		if ((start->number_10) < number_10) {
			//printf("_2\n");
			start = start->right_tree;
		}
		else {
			start = start->left_tree;
			//printf("_3\n");
		}

	}
}

Splay_tree_number* create_new_branch(Splay_tree_number* start, char number_16[100])
{
	
	//printf("%s\n", start->number_16);
	//printf("%s\n", number_16);

	ULL number_10 = invert_16_to_10(number_16);
	Splay_tree_number* nachalo_0 = NULL;
	if (start == NULL) {
		Splay_tree_number* start = (Splay_tree_number*)malloc(sizeof(Splay_tree_number));
		start->number_10 = number_10;
		memcpy(start->number_16, number_16, sizeof(start->number_16));
		start->count = 1;			
		start->parent_tree = NULL;
		start->right_tree = NULL;
		start->left_tree = NULL;
		
		/*printf("%s\n", start->number_16);
		printf("%s\n", start->left_tree);
		printf("%s\n", start->right_tree);*/
		//printf("%s\n", start);

		return start;
		
	}
	nachalo_0 = search_least(start, number_10);
	//printf("%s\n", nachalo_0->number_16);
	if (Flag_global == true) {
		
		// Должна быть функция splay
		splay_tree_func(nachalo_0);
		//printf("%s\n", start);
		return nachalo_0;
	}
	else {
		Splay_tree_number* start_new = (Splay_tree_number*)malloc(sizeof(Splay_tree_number));
		start_new->number_10 = number_10;
		memcpy(start_new->number_16, number_16, sizeof(start->number_16));
		start_new->count = 1;
		start_new->parent_tree = nachalo_0;
		if ((nachalo_0->number_10) < number_10) {
			nachalo_0->right_tree = start_new;
		}
		else {
			nachalo_0->left_tree = start_new;
		}
		start_new->right_tree = NULL;
		start_new->left_tree = NULL;

		// Должна быть функция splay
		//printf("---%s\n", start_new->number_16);
		//printf("--%s\n", start_new->parent_tree->number_16);
		
		splay_tree_func(start_new);
		
		//printf("%s\n", start);
		//printf("%s\n", start_new->number_16);
		return start_new;
	}

}

void print_splay_tree(Splay_tree_number* start) {
	//printf("%s\n", start->number_16);
	if (start != NULL) {
		printf("  number: %s\tcnt: %d\n", start->number_16, start->count);
		//printf("%s\n", start->number_16);
		print_splay_tree(start->left_tree);
		print_splay_tree(start->right_tree);
		//printf("number: %s\tcnt: %d\n", start->number_16, start->count);
	}

}

//char* modification_number(char* number_16_start) {
//	char new_number[98] = "";
//	for (int i = 0; i < strlen(number_16_start); i++) {
//		new_number[i] = number_16_start[2 + i];
//	}
//	printf("%s\n", new_number);
//	return new_number;
//}

Splay_tree_number* create_string(char symbol, char str_of_symbols[100], Splay_tree_number* start) {
	
	
	//int qwe = 0x1fU;
	//Splay_tree_number* start_new = start;
	char separator[] = ", ; ) ]";
	char slesh = -1;
	char numbers_s[] = "0123456789ABCDEFabcdefU";
	char number_with_out_0x[98] = "";
	//char special_symbols[] = "0x";

	if (strlen(str_of_symbols) == 0 && symbol != '0') {
		memset(str_of_symbols, 0, 100);
		return start;
	}

	if ((strlen(str_of_symbols) < 3)) {
		int i = 0;
		while (str_of_symbols[i]) i++;
		str_of_symbols[i] = symbol;
		str_of_symbols[i + 1] = 0;
		return start;
	}

	if (str_of_symbols[0] == '0' && str_of_symbols[1] == 'x') {
		if (!(strchr(numbers_s, str_of_symbols[2]))) {
			memset(str_of_symbols, 0, 100);
			return start;
		}

		if (strchr(numbers_s, symbol)) {
			int i = 0;
			while (str_of_symbols[i]) i++;
			str_of_symbols[i] = symbol;
			str_of_symbols[i + 1] = 0;
			return start;
		}
		else if (strchr(separator, symbol) || (symbol == 10)) {
			//printf("%s\n", str_of_symbols);
			for (int i = 0; i < strlen(str_of_symbols); i++) {
				number_with_out_0x[i] = str_of_symbols[i + 2];
			}
			//printf("%s\n", number_with_out_0x);
			
			start = create_new_branch(start, number_with_out_0x);
			memset(str_of_symbols, 0, 100);
			return start;
		}
		else {
			memset(str_of_symbols, 0, 100);
		}
	}
	memset(str_of_symbols, 0, 100);
	return start;

}

int main(int argc, char** argv)
{
	Splay_tree_number* start = NULL;
	FILE* inp = fopen("test_0.c", "r");
	
	//FileName.cpp

	char keyword[100] = "";
	char c, prev_c = ' ';
	char single_comm = 0, multi_comm = 0, symbol = 0, str_const = 0, multi_comm_opened = 0, multi_comm_closed = 0, back_slash_count = 0;

	/*while (!feof(inp)) {
		c = fgetc(inp);
		start = create_string(c, keyword, start);
	}*/
	//
	//printf("%s\n", start);

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
					if (prev_c == '/' && !multi_comm_closed) {
						//make_string(keyword, prev_c, &keyword_tree_root);
						start = create_string(prev_c, keyword, start);
					}
					str_const = 1;
					back_slash_count = 0;
					symbol = c;
				}
				else {
					if (prev_c == '/' && c == '/' && !multi_comm_closed) {
						single_comm = 1;
						//make_string(keyword, '\n', &keyword_tree_root);
						start = create_string('\n', keyword, start);
					}
					if (prev_c == '/' && c == '*' && !multi_comm_closed) {
						multi_comm = 1;
						multi_comm_opened = 1;
						//make_string(keyword, '\n', &keyword_tree_root);
						start = create_string('\n', keyword, start);
					}
					if (c != '/' && c != '*') {
						if (prev_c == '/' && !multi_comm_closed)
							//make_string(keyword, prev_c, &keyword_tree_root);
							start = create_string(prev_c, keyword, start);
						//make_string(keyword, c, &keyword_tree_root);
						start = create_string(c, keyword, start);
						multi_comm_closed = 0;
					}
				}
			}
		}
		prev_c = c;
	}

	start = create_string(c, keyword, start);
	
	fclose(inp);

	print_splay_tree(start);


}