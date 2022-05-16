
import time
import pandas as pd

def printWelcome():
    # https://www.askapache.com/online-tools/figlet-ascii/
    # https://www.pythonescaper.com/
    print(">   _______          _________ _    _________         _________ _       \r\n"
    ">  (  ____ \\|\\     /|\\__   __/( \\   \\__   __/|\\     /|\\__   __/( (    /|\r\n"
    ">  | (    \\/| )   ( |   ) (   | (      ) (   | )   ( |   ) (   |  \\  ( |\r\n"
    ">  | (__    | |   | |   | |   | |      | |   | | _ | |   | |   |   \\ | |\r\n"
    ">  |  __)   ( (   ) )   | |   | |      | |   | |( )| |   | |   | (\\ \\) |\r\n"
    ">  | (       \\ \\_/ /    | |   | |      | |   | || || |   | |   | | \\   |\r\n"
    ">  | (____/\\  \\   /  ___) (___| (____/\\| |   | () () |___) (___| )  \\  |\r\n"
    ">  (_______/   \\_/   \\_______/(_______/)_(   (_______)\\_______/|/    )_)\n>\n"
    ">   ____________________________________________________\n"
    ">  |                                                    |\n"
    ">  | Utility by Elhai Mansbach, Itay Rafee, Almog Jakov |\n"
    ">  |____________________________________________________|\n>\n"
    ">  (Ctrl-C to abort settings & exit the utility)\n\n")


def printFakeApWelcome():
    print(">   _______  _______  _        _______    _______  _______ \r\n"
    ">  (  ____ \\(  ___  )| \\    /\\(  ____ \\  (  ___  )(  ____ )\r\n"
    ">  | (    \\/| (   ) ||  \\  / /| (    \\/  | (   ) || (    )|\r\n"
    ">  | (__    | (___) ||  (_/ / | (__      | (___) || (____)|\r\n"
    ">  |  __)   |  ___  ||   _ (  |  __)     |  ___  ||  _____)\r\n"
    ">  | (      | (   ) ||  ( \\ \\ | (        | (   ) || (      \r\n"
    ">  | )      | )   ( ||  /  \\ \\| (____/\\  | )   ( || )      \r\n"
    ">  |/       |/     \\||_/    \\/(_______/  |/     \\||/ \n\n"
    "   Ctrl-C to exit this window (wait for auto closing)\n"
    "   ########################################################\n\n")

def loadingCircle(msg):
    animation = "◷◶◵◴" # "|/-\\"
    idx = 0
    print()
    while True:
        print(">  "+str(animation[idx % len(animation)] + "  "+msg), end="\r")
        idx += 1
        time.sleep(0.1)

def loadingProgressBar(timeout, first, last):
    items = list(range(0, 100))
    l = len(items)
    # Initial call to print 0% progress
    printProgressBar(0, l, prefix = ">  "+first+":", suffix = last, length = 46)
    for i, item in enumerate(items):
        # Do stuff...
        time.sleep(timeout/100)
        # Update Progress Bar
        printProgressBar(i + 1, l, prefix = ">  "+first+":", suffix = last, length = 46)
    print('')

# https://stackoverflow.com/questions/3173320/text-progress-bar-in-terminal-with-block-characters
# Print iterations progress
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()


# https://stackoverflow.com/questions/18528533/pretty-printing-a-pandas-dataframe
def tableize(df):
    if not isinstance(df, pd.DataFrame):
        return
    df_columns = df.columns.tolist() 
    max_len_in_lst = lambda lst: len(sorted(lst, reverse=True, key=len)[0])
    align_center = lambda st, sz: "{0}{1}{0}".format(" "*(1+(sz-len(st))//2), st)[:sz] if len(st) < sz else st
    align_right = lambda st, sz: "{0}{1} ".format(" "*(sz-len(st)-1), st) if len(st) < sz else st
    max_col_len = max_len_in_lst(df_columns)
    max_val_len_for_col = dict([(col, max_len_in_lst(df.iloc[:,idx].astype('str'))) for idx, col in enumerate(df_columns)])
    col_sizes = dict([(col, 2 + max(max_val_len_for_col.get(col, 0), max_col_len)) for col in df_columns])
    build_hline = lambda row: '+'.join(['-' * col_sizes[col] for col in row]).join(['+', '+'])
    build_data = lambda row, align: "|".join([align(str(val), col_sizes[df_columns[idx]]) for idx, val in enumerate(row)]).join(['|', '|'])
    hline = build_hline(df_columns)
    out = [hline, build_data(df_columns, align_center), hline]
    for _, row in df.iterrows():
        out.append(build_data(row.tolist(), align_right))
    out.append(hline)
    return "\n".join(out)