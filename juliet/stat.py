import os
import sys
import pandas as pd



if __name__ == '__main__':
    result_folder = sys.argv[1]
    target_paths = os.walk(result_folder)

    bad_results = []
    good_results = []

    for root, directories, files in target_paths:
        for file in files:
            if file.endswith("bad.csv"):
                df =  pd.read_csv(os.path.join(root,file))
                count = df.shape[0]
                asan_passed = df['Asan'].sum()
                rezzan_passed = df['ReZZan'].sum()
                lite_passed = df['ReZZan_lite'].sum()
                bad_results.append((file[:file.find('_')], file.split("_")[-2], count, asan_passed, rezzan_passed, lite_passed))
            elif file.endswith("good.csv"):
                df =  pd.read_csv(os.path.join(root,file))
                count = df.shape[0]
                asan_passed = count - df['Asan'].sum()
                rezzan_passed = count - df['ReZZan'].sum()
                lite_passed = count - df['ReZZan_lite'].sum()
                good_results.append((file[:file.find('_')], file.split("_")[-1], count, asan_passed, rezzan_passed, lite_passed))

    bad_df = pd.DataFrame(bad_results, columns=['CWE','subvolumn','total','Asan','ReZZan','ReZZan_lite'])
    good_df = pd.DataFrame(good_results, columns=['CWE','subvolumn','total','Asan','ReZZan','ReZZan_lite'])

    print("--------------------------------------------------------------------------------------")
    print("Passed number in bad test cases:")
    print(bad_df.groupby(['CWE']).agg(
     total = ('total','sum'),
     Asan = ('Asan','sum'),
     ReZZan = ('ReZZan','sum'),
     ReZZan_lite = ('ReZZan_lite','sum'),
        ).reset_index())

    print("\n")
    print("Passed number in good test cases:")
    print(good_df.groupby(['CWE']).agg(
     total = ('total','sum'),
     Asan = ('Asan','sum'),
     ReZZan = ('ReZZan','sum'),
     ReZZan_lite = ('ReZZan_lite','sum'),
        ).reset_index())
