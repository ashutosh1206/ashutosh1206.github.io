---
title: "Polynomial Interpolation"
date: 2017-05-31
author: Ashutosh Ahelleya
math: true
---

I have been reading the paper -- [“How to Share a Secret”](http://passguardian.com/assets/1979_HowToShareASecret_Shamir.pdf) in detail for the past few weeks, a revolutionary research paper written by Adi Shamir. This paper, applies some of the concepts of Number Theory and Algebra, one of which is polynomial interpolation, and has been used to construct a secure and reliable key management system. The theorem is simple and easy to understand, and has been applied in the best way one ever could.

## Theorem - Uniqueness of Polynomial Interpolation

Consider n+1 unequal coordinates \\((x_0,y_0)\\),\\((x_1,y_1)\\),\\((x_2,y_2)\\),...,\\((x_n,y_n)\\). According to the theorem of uniqueness of polynomial interpolation, there exists at most one polynomial \\(p\\) of degree less than or equal to \\(n\\) such that:
$$p(x_i)=y_i;\;\;\;i=0,...,n$$

Remember the uniqueness for the satisfying polynomial is only for a particular degree. There can exist two polynomials of different degrees which contain all of these points.

## Proof
We are going to prove this theorem by contradiction.

Let us assume that there exist two polynomials \\(p_1\\) and \\(p_2\\) of degree less than or equal to \\(n\\), that satisfies:
$$p_1(x_i) = p_2(x_i) = y_i;\\;\\;\\;i=0,...,n$$

This implies: All the points lie on the graphs of \\(p_1\\) and \\(p_2\\). So, one can conclude that at these points, the difference between the polynomials is zero since the value is same for both of the polynomials on that point. We can generalize this as:
$$q(x_i) = p_1(x_i) - p_2(x_i);\;\;\; i=0,...,n$$

The degree of the polynomial \\(q(x_i)\\) is same as that of \\(p_1\\) and \\(p_2\\) i.e. less than or equal to \\(n\\). We can conclude from the above that:
$$q(x_i) = 0;\;\;\; i=0,...,n$$

Clearly, the polynomial has \\(n+1\\) zeros. How is it possible? How can a polynomial of degree <= \\(n\\) have \\(n+1\\) zeros? Yes, it can happen only when the polynomial \\(q(x_i)\\) is a zero polynomial i.e. value of \\(q\\) is zero for all values of \\(x\\) in the Cartesian Plane.

Now, since \\(q\\) is a zero polynomial, we can write:
$$q(x_i) = p_1(x_i) - p_2(x_i)$$
$$0 = p_1(x_i) - p_2(x_i)$$
$$p_1(x_i) = p_2(x_i)$$

Thus we have proved that the polynomials \\(p_2\\) and \\(p_1\\) are identical polynomials, making our assumption wrong. Hence, we have proved the theorem mentioned above by method of contradiction!
