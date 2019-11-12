pkg load econometrics

timing = csvread('attack_smother_time.csv');
timing0 = timing(1, :);
timing1  = timing(2, :);

[hist0, b0] = hist(timing0, [0:2:100]);
[hist1, b1] = hist(timing1, [0:2:100]);

len = size(b0)(1,2) - 1;
hist0 = hist0(:, 1:len);
b0 = b0(:, 1:len);
hist1 = hist1(:, 1:len);
b1 = b1(:, 1:len);

kernel_range = [60:0.1:100]';
dens0 = kernel_density(kernel_range, timing0', 1);
dens1 = kernel_density(kernel_range, timing1', 1);
# plot(b0, hist0, 'LineWidth', 2, b1, hist1, 'LineWidth', 2);
plot(kernel_range, dens1, 'LineWidth', 1, 'Color', 'blue', 'linestyle', '--', kernel_range, dens0, 'LineWidth', 1, 'Color', 'red');
l = legend('secret = 1', 'secret = 0');
set (l, "fontsize", 14);
l = xlabel ('Timestamp counter difference');
set (l, "fontsize", 14);
l = ylabel ('Probability');
set (l, "fontsize", 14);
print -dpng dist.png

size(timing0)
size(timing1)
mean(timing0)
mean(timing1)
median(timing0)
median(timing1)