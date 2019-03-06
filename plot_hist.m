attack = csvread('attack_time.csv');
victim = csvread('victim_secret.csv');
n_samples = size(attack, 2) - 1

attack0 = sum(attack(find(victim == 0), :), 2) / n_samples;
attack1 = sum(attack(find(victim == 1), :), 2) / n_samples;

[hist0, b0] = hist(attack0, [20: 2: 200]); 
[hist1, b1] = hist(attack1, [20: 2: 200]);

plot(b0, hist0, 'LineWidth', 2, b1, hist1, 'LineWidth', 2);
legend('secret = 0', 'secret = 1');
xlabel ('Timestamp counter difference');
ylabel ('Number of samples');