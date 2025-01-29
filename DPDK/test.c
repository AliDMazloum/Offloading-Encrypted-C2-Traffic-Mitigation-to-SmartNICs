#include <stdio.h>
#include <stdbool.h>
#include <string.h>

bool wildcard_match(const char *pattern, const char *text) {
    // Pointers to track positions in pattern and text
    const char *pp = pattern;
    const char *tp = text;
    const char *last_star = NULL;
    const char *last_tp = NULL;

    while (*tp != '\0') {
        if (*pp == '*') {
            last_star = pp++;
            last_tp = tp;
        } else if (*pp == '?' || *pp == *tp) {
            pp++;
            tp++;
        } else if (last_star != NULL) {
            pp = last_star + 1;
            tp = ++last_tp;
        } else {
            return false;
        }
    }

    // Skip remaining '*' in pattern
    while (*pp == '*') {
        pp++;
    }

    return (*pp == '\0');
}

int main() {
    const char *pattern = "h*ll*o";
    const char *text1 = "hello";
    const char *text2 = "hallo";
    const char *text3 = "helllllo";
    const char *text4 = "helo";

    printf("Pattern: %s\n", pattern);
    printf("Text: %s, Match: %s\n", text1, wildcard_match(pattern, text1) ? "Yes" : "No");
    printf("Text: %s, Match: %s\n", text2, wildcard_match(pattern, text2) ? "Yes" : "No");
    printf("Text: %s, Match: %s\n", text3, wildcard_match(pattern, text3) ? "Yes" : "No");
    printf("Text: %s, Match: %s\n", text4, wildcard_match(pattern, text4) ? "Yes" : "No");

    return 0;
}
