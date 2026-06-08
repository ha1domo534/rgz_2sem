#include "rgz.h"

int main(int argc, char* argv[]) {
    struct Arguments args;
    if (parse_arguments(argc, argv, &args) != 0) {
        print_help(argv[0]);
        return 1;
    }
    if (args.help) {
        print_help(argv[0]);
        return 0;
    }
    return process_data(&args);
}