# Log-Analysis-Script

It counts requests per IP address and displays them in descending order.
It identifies the most frequently accessed endpoint and its access count.
It detects suspicious activity by flagging IP addresses with failed login attempts exceeding a configurable threshold.
It displays the results in the terminal and saves them to a CSV file in the specified format.

I'll provide you with a step-by-step approach to tackle this log analysis assignment. Here's how we can break it down:

Step 1: Set up the project

1. Create a new Python file, e.g., `log_analyzer.py`.
2. Import necessary libraries (re, collections, csv).


Step 2: Define helper functions

1. Create a function to parse log lines and extract relevant information.
2. Create functions for each analysis task (count requests, find most accessed endpoint, detect suspicious activity).


Step 3: Implement the main analysis function

1. Create a function that reads the log file and calls the helper functions.
2. Use appropriate data structures (e.g., defaultdict) to store results efficiently.


Step 4: Implement result output functions

1. Create a function to display results in the terminal.
2. Create a function to save results to a CSV file.


Step 5: Write the main execution block

1. Set up command-line argument parsing for the log file path.
2. Call the main analysis function and output functions.

Now, let's go through how to use this script:

1. Save the above code in a file named `log_analyzer.py`.
2. Open a terminal or command prompt.
3. Navigate to the directory containing `log_analyzer.py` and `sample.log`.
4. Run the script with the following command:


python log_analyzer.py sample.log


This will analyze the `sample.log` file and display the results in the terminal. It will also create a CSV file named `log_analysis_results.csv` with the analysis results.


You can customize the output file name and suspicious activity threshold using command-line arguments:

python log_analyzer.py sample.log --output custom_results.csv --threshold 5
