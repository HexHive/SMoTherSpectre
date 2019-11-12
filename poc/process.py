#!/usr/bin/python3
import statistics
import csv
import sys
import subprocess as oss

def build(nsample, threshold, use_pmc = 1):
    oss.call(['make', 'clean'])
    oss.call(['make', 'NSAMPLES='+str(nsample), 
              'THRESHOLD='+str(threshold),
              'USE_PMC='+str(use_pmc)])

def run_expt():
    oss.call(['./orchestrator'])

def get_accuracy(nsample = 2, threshold = 94):
    build(nsample, threshold)
    run_expt()

    attack_guess = [int(i[0]) for i in list(csv.reader(open('attack_guess.csv')))]
    victim_secret = [int(i[0]) for i in list(csv.reader(open('victim_secret.csv')))]

    correct = 0
    for pair in zip(attack_guess, victim_secret):
        if (pair[0] == pair[1]):
            correct += 1

    return (correct / len(attack_guess))

def main(threshold = -1):
    acc_list = {}
    for nsample in range(1, 10):
        if threshold == -1:
            acc = get_accuracy(nsample)
        else:
            acc = get_accuracy(nsample, threshold)
        acc_list[nsample] = acc
        
    for nsample in range(1, 10):
        print("Accuracy for", nsample, "samples per expt is ", acc_list[nsample])

if __name__ == "__main__":
    if(len(sys.argv) > 1):
        main(int(sys.argv[1]))
    else:
        main()
