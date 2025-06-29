def maxSubarray(nums):
  max_sum=current_sum=nums[0]
  for num in range(nums[1:]):
    current_sum=max(nums,current_sum+num)
    max_sum=max(max_sum,current_sum)

  return max_sum
print(maxSubarray([-2,1,-3,4,-1,2,1,-5,4]))