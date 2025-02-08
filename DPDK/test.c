#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define MAX_TREES 100
#define MAX_NODES 500

// Structure to hold tree node information
typedef struct {
    int feature;
    double threshold;
    int left_child;
    int right_child;
    int is_leaf;
    int class_label;
} TreeNode;

// Structure to hold random forest model
typedef struct {
    int n_estimators;
    int max_depth;
    double feature_importances[4];
    TreeNode trees[MAX_TREES][MAX_NODES];
} RandomForest;

// Function to read the JSON file and load the Random Forest model
int load_rf_model(const char *filename, RandomForest *rf) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);

    if (!root) {
        fprintf(stderr, "Error loading JSON file: %s\n", error.text);
        return -1;
    }

    // Parse the general model parameters
    json_t *n_estimators = json_object_get(root, "n_estimators");
    json_t *max_depth = json_object_get(root, "max_depth");
    json_t *feature_importances = json_object_get(root, "feature_importances");

    rf->n_estimators = json_integer_value(n_estimators);
    rf->max_depth = json_integer_value(max_depth);

    // Parse feature importances
    for (int i = 0; i < 4; i++) {
        rf->feature_importances[i] = json_real_value(json_array_get(feature_importances, i));
    }

    // Parse each decision tree
    json_t *estimators = json_object_get(root, "estimators");
    size_t index;
    json_t *tree_data;

    json_array_foreach(estimators, index, tree_data) {
        TreeNode *tree = rf->trees[index];
        size_t n_nodes = json_integer_value(json_object_get(tree_data, "n_nodes"));

        // Parse the nodes of the tree
        json_t *children_left = json_object_get(tree_data, "children_left");
        json_t *children_right = json_object_get(tree_data, "children_right");
        json_t *feature = json_object_get(tree_data, "feature");
        json_t *threshold = json_object_get(tree_data, "threshold");

        for (int i = 0; i < n_nodes; i++) {
            TreeNode *node = &tree[i];
            node->feature = json_integer_value(json_array_get(feature, i));
            node->threshold = json_real_value(json_array_get(threshold, i));
            node->left_child = json_integer_value(json_array_get(children_left, i));
            node->right_child = json_integer_value(json_array_get(children_right, i));

            // Determine if it's a leaf node (no children)
            if (node->left_child == -1 && node->right_child == -1) {
                node->is_leaf = 1;
                node->class_label = json_integer_value(json_object_get(tree_data, "class_label"));
            } else {
                node->is_leaf = 0;
            }
        }
    }

    json_decref(root);
    return 0;
}

// Function to traverse a tree and make a prediction
int predict_tree(TreeNode *tree, double *sample, int node_index) {
    TreeNode *node = &tree[node_index];

    if (node->is_leaf) {
        return node->class_label;
    }

    if (sample[node->feature] <= node->threshold) {
        return predict_tree(tree, sample, node->left_child);
    } else {
        return predict_tree(tree, sample, node->right_child);
    }
}

// Function to make a prediction using the Random Forest
int predict(RandomForest *rf, double *sample) {
    int predictions[MAX_TREES];
    int final_prediction = 0;

    for (int i = 0; i < rf->n_estimators; i++) {
        predictions[i] = predict_tree(rf->trees[i], sample, 0);
    }

    // Majority voting for classification
    int count[3] = {0};  // Assuming 3 possible classes
    for (int i = 0; i < rf->n_estimators; i++) {
        count[predictions[i]]++;
    }

    // Find the majority vote
    for (int i = 0; i < 3; i++) {
        if (count[i] > count[final_prediction]) {
            final_prediction = i;
        }
    }

    return final_prediction;
}

int main() {
    // Initialize random forest
    RandomForest rf;

    // Load the model from the JSON file
    if (load_rf_model("rf_model.json", &rf) != 0) {
        return -1;
    }

    // Example input sample (e.g., from Iris dataset)
    double sample[4] = {5.1, 3.5, 1.4, 0.2};  // Sample to classify

    // Make a prediction
    int prediction = predict(&rf, sample);

    printf("Predicted class: %d\n", prediction);

    return 0;
}
