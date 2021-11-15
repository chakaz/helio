// Copyright 2013, Beeri 15.  All rights reserved.
// Author: Roman Gershman (romange@gmail.com)
//
#include "base/histogram.h"
#include "base/integral_types.h"
#include "base/logging.h"

#include <gtest/gtest.h>

namespace base {

static constexpr double kNums[] = {
17673.6, 571.576, 222.006, 2350.53, 712.773, 125.278, 911.046, 547.236, 764.302, 530.025, 181.904,
237.308, 286.248, 66.5836, 332.369, 33.4577, 260.28, 239.985, 847.661, 16.325, 367.061,
1100.58, 1852.5, 88.5581, 436.41, 466.658, 568.58, 144.01, 20711, 40.5508, 538.038, 278.472,
4.92752, 661.735, 1750.9, 282.776, 274.315, 601.877, 75.233, 111.384,  47.4329, 332.011,
451.953, 351.846, 24392.4, 4631.78, 1283.76, 79.9646, 32.3762, 733.843, 79.2507, 401.516, 247.944,
164.122, 117.451, 724.058, 578.508, 242.581, 482.022, 1064.87, 197.336, 943.112, 722.428,
91.6888, 819.899, 989.001, 371.356, 373.563, 178.684, 353.012, 725.824, 816.289, 849.877,
585.985, 417.934, 1416.77, 424.519, 138.568, 847.251, 254.831, 378.742, 283.602, 622.917, 2089.97,
1490.45, 1316.68, 1293.48, 214.369, 65.2874, 862.771, 10.755, 332.479, 677.26, 503.86, 1137.2,
2062.12, 72.4223, 324.663, 292.947,   67.4108, 17.7525, 53.9887, 1368.34, 44.1126, 180.346, 522.2,
296.671, 457.535, 127.567, 1468.2, 204.619, 95.9224, 1616.53, 513.349, 714.977, 426.308, 480.946,
111.742, 1629.34,  1097.43, 920.192, 1393.15, 190.53, 7.29437, 32.5502, 310.045, 49.4946, 476.17,
560.602, 623.841, 225.658, 110.05, 189.132, 1688.47, 648.619, 1283.5, 23.9636, 49512.7, 848.896,
800.885, 172.147, 335.425, 194.722, 1566.86, 229.435, 474.353, 662.451, 216.356, 475.097,
1440.58, 140.904, 606.091, 380.24, 528.514, 205.61, 23.8672, 920.171, 1489.7, 35.3736,  549.543,
839.611, 687.68, 1241.66, 336.56, 793.859, 2219.83, 24924.1, 32.0011, 126.73, 214.031, 41.5238,
54.8806, 368.541, 350.531, 1029.66, 20.4166, 14.2737, 349.279, 759.657,  2060.77, 1074.93,
271.469, 78.5938, 110.687, 368.696, 252.788, 255.126, 168.9, 36.9738, 280.664, 12.0113, 511.576,
1699.88, 312.428, 250.905, 307.282, 110.883, 689.759, 272.036, 436.521, 1075.7, 53.9167,
141.435, 18.4813, 99.2972, 152.864, 172.067, 17.7525, 2.56733e+06, 186.404, 198.975, 344.428,
193.662, 333.893, 250.785, 227.799, 383.966, 581.648, 571.495, 221.86, 1830.6, 235.581,
399.325, 403.02, 31.6297, 876.051, 1018.68, 345.852, 45.2074, 328.094, 1011.9, 352.182, 52.7133,
2092.04, 628.605, 199.908, 1211.79, 140.263, 56.2181, 257.504, 777.83, 28.9148, 166.161, 425.155,
51.8636, 308.919, 118.446, 189.702, 28.9833, 292.325, 947.967, 1182.06, 4.02723, 1225.64, 457.235,
479.456, 298.505, 313.241, 207.288, 6051.56, 648.337, 19.7162, 1081.95, 88.0572, 1605.94,
178.107, 17.7525, 1779.12, 181.181, 728.427, 52, 465.271, 494.857, 123.179, 246.911, 22.2814,
813.072, 632.849, 443.847, 167.885, 524.883, 992.897, 16.1542, 3501.63, 837.231, 92.6868,
192.339, 329.824, 271.476, 801.613};

class HistogramTest : public testing::Test {
protected:
  Histogram hist_;
};

TEST_F(HistogramTest, Basic) {
  EXPECT_LT(sizeof(hist_), 100);
  for (int i = 0; i < 100; ++i) {
    hist_.Add(10);
  }
  EXPECT_EQ(10, hist_.Average());
  // EXPECT_EQ(10, hist_.TruncatedMean(0, 0));
  // EXPECT_NEAR(10, hist_.TruncatedMean(1, 1), 0.3);
}

TEST_F(HistogramTest, Grow) {
  for (int i = 0; i < 100; ++i) {
    hist_.Add(i * i);
  }
  for (int i = 0; i < 20; ++i)
    hist_.Add(1);
  LOG(INFO) << hist_.ToString();
}

#if 0
TEST_F(HistogramTest, FewNumbers) {
  for (int i = 0; i < 3; ++i) {
    hist_.Add(10);
  }
  EXPECT_EQ(10, hist_.TruncatedMean(5, 5));
}

TEST_F(HistogramTest, TestNums) {
  for (int i = 0; i < arraysize(kNums); ++i) {
    hist_.Add(kNums[i]);
  }
  EXPECT_EQ(10, hist_.TruncatedMean(5, 5));
}
#endif

}  // namespace base
