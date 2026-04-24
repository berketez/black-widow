"""Sablon-bazli formul ciktisi.

Tespit edilen algoritmalari insanin okuyabilecegi formullere donusturur.
LaTeX, ASCII ve method/reference bilgisi uretir.

Kullanim:
    from karadul.reconstruction.engineering.formula_reconstructor import FormulaReconstructor
    from karadul.reconstruction.c_algorithm_id import AlgorithmMatch

    reconstructor = FormulaReconstructor()
    formulas = reconstructor.reconstruct(detected_algorithms)
    report_md = reconstructor.generate_report(formulas)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch


# -----------------------------------------------------------------------
# FormulaInfo dataclass
# -----------------------------------------------------------------------

@dataclass
class FormulaInfo:
    """Tespit edilen bir algoritmanin formul bilgisi.

    Attributes:
        algorithm: Algoritma adi (eslesen AlgorithmMatch.name).
        latex: LaTeX formul gosterimi.
        ascii: ASCII/plain text formul gosterimi.
        method: Yontemin kisa aciklamasi.
        reference: Akademik referans (kitap/makale).
        parameters: Opsiyonel parametre tablosu.
    """
    algorithm: str
    latex: str
    ascii: str
    method: str
    reference: str
    parameters: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "algorithm": self.algorithm,
            "latex": self.latex,
            "ascii": self.ascii,
            "method": self.method,
            "reference": self.reference,
        }
        if self.parameters:
            d["parameters"] = self.parameters
        return d


# -----------------------------------------------------------------------
# Formula templates (40+)
# -----------------------------------------------------------------------

FORMULA_TEMPLATES: dict[str, FormulaInfo] = {
    # ==================================================================
    # NUMERICAL INTEGRATION / GAUSS QUADRATURE
    # ==================================================================

    "gauss_quadrature_1pt": FormulaInfo(
        algorithm="Gauss Quadrature 1-point",
        latex=r"\int_{-1}^{1} f(\xi)\,d\xi \approx 2\,f(0)",
        ascii="int[-1,1] f(xi) dxi ~ 2*f(0)",
        method="1-point Gauss-Legendre quadrature. Exact for polynomials up to degree 1.",
        reference="Zienkiewicz, Taylor & Zhu, 'The Finite Element Method', 7th ed., Ch.5",
        parameters={"points": "1", "weights": "w1=2.0", "nodes": "xi1=0.0"},
    ),

    "gauss_quadrature_2pt": FormulaInfo(
        algorithm="Gauss Quadrature 2-point",
        latex=r"\int_{-1}^{1} f(\xi)\,d\xi \approx f\!\left(-\frac{1}{\sqrt{3}}\right) + f\!\left(\frac{1}{\sqrt{3}}\right)",
        ascii="int[-1,1] f(xi) dxi ~ f(-1/sqrt(3)) + f(1/sqrt(3))",
        method="2-point Gauss-Legendre quadrature. Exact for polynomials up to degree 3.",
        reference="Zienkiewicz, Taylor & Zhu, 'The Finite Element Method', 7th ed., Ch.5",
        parameters={"points": "2", "weights": "w1=w2=1.0", "nodes": "xi=+-0.577350269"},
    ),

    "gauss_quadrature_3pt": FormulaInfo(
        algorithm="Gauss Quadrature 3-point",
        latex=r"\int_{-1}^{1} f(\xi)\,d\xi \approx \tfrac{5}{9}f\!\left(-\sqrt{\tfrac{3}{5}}\right) + \tfrac{8}{9}f(0) + \tfrac{5}{9}f\!\left(\sqrt{\tfrac{3}{5}}\right)",
        ascii="int[-1,1] f(xi) dxi ~ (5/9)*f(-sqrt(3/5)) + (8/9)*f(0) + (5/9)*f(sqrt(3/5))",
        method="3-point Gauss-Legendre quadrature. Exact for polynomials up to degree 5.",
        reference="Zienkiewicz, Taylor & Zhu, 'The Finite Element Method', 7th ed., Ch.5",
        parameters={
            "points": "3",
            "weights": "w1=w3=5/9, w2=8/9",
            "nodes": "xi1=-0.774596669, xi2=0.0, xi3=0.774596669",
        },
    ),

    "gauss_quadrature_2x2": FormulaInfo(
        algorithm="Gauss Quadrature 2x2",
        latex=r"\iint f(\xi,\eta)\,d\xi\,d\eta \approx \sum_{i=1}^{2}\sum_{j=1}^{2} w_i w_j\,f(\xi_i,\eta_j)",
        ascii="int int f(xi,eta) dxi deta ~ sum_i sum_j w_i*w_j*f(xi_i,eta_j), 2x2 pts",
        method="2x2 Gauss-Legendre quadrature for 2D elements. 4 integration points total.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.5",
        parameters={
            "points": "2x2=4",
            "weights": "w_i=1.0",
            "nodes": "xi,eta = +-1/sqrt(3)",
        },
    ),

    "gauss_quadrature_2x2x2": FormulaInfo(
        algorithm="Gauss Quadrature 2x2x2",
        latex=r"\iiint f(\xi,\eta,\zeta)\,d\xi\,d\eta\,d\zeta \approx \sum_{i,j,k=1}^{2} w_i w_j w_k\,f(\xi_i,\eta_j,\zeta_k)",
        ascii="int int int f(xi,eta,zeta) ~ sum_ijk w_i*w_j*w_k*f(xi_i,eta_j,zeta_k), 2x2x2",
        method="2x2x2 Gauss-Legendre quadrature for 3D hex elements. 8 integration points.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.5",
        parameters={"points": "2x2x2=8", "weights": "w_i=1.0", "nodes": "+-1/sqrt(3)"},
    ),

    "gauss_quadrature_3x3x3": FormulaInfo(
        algorithm="Gauss Quadrature 3x3x3",
        latex=r"\iiint f\,d\xi\,d\eta\,d\zeta \approx \sum_{i,j,k=1}^{3} w_i w_j w_k\,f(\xi_i,\eta_j,\zeta_k)",
        ascii="int int int f ~ sum_ijk w_i*w_j*w_k*f(xi_i,eta_j,zeta_k), 3x3x3=27 pts",
        method="3x3x3 Gauss-Legendre quadrature for 3D hex elements. 27 integration points.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.5",
        parameters={
            "points": "3x3x3=27",
            "weights": "5/9, 8/9, 5/9",
            "nodes": "+-0.7746, 0.0",
        },
    ),

    # ==================================================================
    # NONLINEAR SOLVERS
    # ==================================================================

    "newton_raphson": FormulaInfo(
        algorithm="Newton-Raphson",
        latex=r"x_{n+1} = x_n - \frac{f(x_n)}{f'(x_n)}",
        ascii="x_{n+1} = x_n - f(x_n) / f'(x_n)",
        method="Newton-Raphson iterative root-finding. Quadratic convergence near root.",
        reference="Burden & Faires, 'Numerical Analysis', 10th ed., Ch.2",
        parameters={"convergence": "quadratic", "tolerance": "1e-6..1e-12"},
    ),

    # ==================================================================
    # ITERATIVE SOLVERS
    # ==================================================================

    "conjugate_gradient": FormulaInfo(
        algorithm="Conjugate Gradient",
        latex=r"\begin{aligned} r_0 &= b - Ax_0,\; p_0 = r_0 \\ \alpha_k &= \frac{r_k^T r_k}{p_k^T A p_k} \\ x_{k+1} &= x_k + \alpha_k p_k \\ r_{k+1} &= r_k - \alpha_k A p_k \\ \beta_k &= \frac{r_{k+1}^T r_{k+1}}{r_k^T r_k} \\ p_{k+1} &= r_{k+1} + \beta_k p_k \end{aligned}",
        ascii="r0=b-Ax0, p0=r0; alpha=rTr/(pTAp); x+=alpha*p; r-=alpha*Ap; beta=r'Tr'/rTr; p=r'+beta*p",
        method="Conjugate Gradient method for SPD systems. O(n*sqrt(kappa)) convergence.",
        reference="Hestenes & Stiefel (1952); Saad, 'Iterative Methods for Sparse Linear Systems', Ch.6",
        parameters={"requirement": "A must be SPD", "convergence": "O(sqrt(cond(A))) iterations"},
    ),

    "gmres": FormulaInfo(
        algorithm="GMRES",
        latex=r"x_m = x_0 + V_m y_m, \quad y_m = \arg\min_y \|H_{m+1,m} y - \beta e_1\|",
        ascii="x_m = x0 + V_m * y_m, y_m = argmin ||H*y - beta*e1||, Arnoldi basis",
        method="Generalized Minimal Residual method. For non-symmetric systems.",
        reference="Saad & Schultz (1986); Saad, 'Iterative Methods for Sparse Linear Systems', Ch.6",
        parameters={"restart": "typically 30-50", "preconditioner": "ILU, Jacobi, etc."},
    ),

    "bicgstab": FormulaInfo(
        algorithm="BiCGSTAB",
        latex=r"\begin{aligned} \rho_k &= \hat{r}_0^T r_k \\ p_k &= r_k + \beta(p_{k-1} - \omega_{k-1} A p_{k-1}) \\ s &= r_k - \alpha A p_k \\ x_{k+1} &= x_k + \alpha p_k + \omega s \end{aligned}",
        ascii="rho=r0hat.T*r; p=r+beta*(p_old-omega*Ap); s=r-alpha*Ap; x+=alpha*p+omega*s",
        method="Biconjugate Gradient Stabilized. For non-symmetric systems, avoids GMRES restart.",
        reference="van der Vorst (1992); Saad, 'Iterative Methods for Sparse Linear Systems', Ch.7",
    ),

    "preconditioned_cg": FormulaInfo(
        algorithm="Preconditioned Conjugate Gradient",
        latex=r"\begin{aligned} r_0 &= b - Ax_0, \; z_0 = M^{-1}r_0 \\ \alpha_k &= \frac{r_k^T z_k}{p_k^T A p_k} \\ x_{k+1} &= x_k + \alpha_k p_k \\ r_{k+1} &= r_k - \alpha_k A p_k \\ z_{k+1} &= M^{-1} r_{k+1} \end{aligned}",
        ascii="z=M^{-1}r; alpha=rTz/(pTAp); x+=alpha*p; r-=alpha*Ap; z=M^{-1}r_new; beta=rTz_new/rTz",
        method="Preconditioned CG. M approximates A, reducing condition number.",
        reference="Saad, 'Iterative Methods for Sparse Linear Systems', Ch.9",
        parameters={"preconditioners": "Jacobi, SSOR, ILU, AMG"},
    ),

    # ==================================================================
    # DIRECT SOLVERS
    # ==================================================================

    "lu_decomposition": FormulaInfo(
        algorithm="LU Decomposition",
        latex=r"A = LU, \quad Ly = b, \quad Ux = y",
        ascii="A = L*U; solve Ly=b (forward sub); solve Ux=y (back sub)",
        method="LU factorization with forward/backward substitution. O(n^3/3) flops.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.3",
        parameters={"complexity": "O(2n^3/3)", "pivoting": "partial or complete"},
    ),

    "cholesky": FormulaInfo(
        algorithm="Cholesky Decomposition",
        latex=r"A = LL^T, \quad L_{ii} = \sqrt{A_{ii} - \sum_{k=1}^{i-1} L_{ik}^2}",
        ascii="A = L*L^T; L_ii = sqrt(A_ii - sum(L_ik^2))",
        method="Cholesky factorization for SPD matrices. Half the cost of LU.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.4",
        parameters={"complexity": "O(n^3/3)", "requirement": "A must be SPD"},
    ),

    # ==================================================================
    # EIGENVALUE METHODS
    # ==================================================================

    "qr_eigenvalue": FormulaInfo(
        algorithm="QR Algorithm (Eigenvalue)",
        latex=r"A_k = Q_k R_k, \quad A_{k+1} = R_k Q_k \rightarrow \text{diag}(\lambda_1, \ldots, \lambda_n)",
        ascii="A_k = Q_k*R_k; A_{k+1} = R_k*Q_k -> converges to eigenvalues on diagonal",
        method="QR iteration with shifts for eigenvalue computation.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.7",
        parameters={"complexity": "O(n^3) per iteration", "shift": "Wilkinson or Rayleigh"},
    ),

    "power_iteration": FormulaInfo(
        algorithm="Power Iteration",
        latex=r"v_{k+1} = \frac{Av_k}{\|Av_k\|}, \quad \lambda \approx v_k^T A v_k",
        ascii="v_{k+1} = A*v_k / ||A*v_k||; lambda ~ v^T*A*v (Rayleigh quotient)",
        method="Power method for dominant eigenvalue. Linear convergence rate |lambda2/lambda1|.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.7",
        parameters={"convergence": "|lambda_2/lambda_1| per iteration"},
    ),

    # ==================================================================
    # TIME INTEGRATION
    # ==================================================================

    "newmark_beta": FormulaInfo(
        algorithm="Newmark-Beta",
        latex=r"\begin{aligned} u_{n+1} &= u_n + \Delta t\,\dot{u}_n + \Delta t^2\left[(\tfrac{1}{2}-\beta)\ddot{u}_n + \beta\,\ddot{u}_{n+1}\right] \\ \dot{u}_{n+1} &= \dot{u}_n + \Delta t\left[(1-\gamma)\ddot{u}_n + \gamma\,\ddot{u}_{n+1}\right] \end{aligned}",
        ascii="u_{n+1} = u_n + dt*udot + dt^2*[(1/2-beta)*uddot_n + beta*uddot_{n+1}]; udot_{n+1} = udot_n + dt*[(1-gamma)*uddot_n + gamma*uddot_{n+1}]",
        method="Newmark-beta time integration. beta=1/4,gamma=1/2: avg acceleration (unconditionally stable).",
        reference="Newmark (1959); Bathe, 'Finite Element Procedures', 2nd ed., Ch.9",
        parameters={
            "beta": "1/4 (avg accel), 1/6 (linear accel)",
            "gamma": "1/2 (no numerical damping)",
            "stability": "unconditionally stable for beta>=gamma/2>=1/4",
        },
    ),

    "hht_alpha": FormulaInfo(
        algorithm="HHT-Alpha",
        latex=r"M\ddot{u}_{n+1} + (1+\alpha)C\dot{u}_{n+1} - \alpha C\dot{u}_n + (1+\alpha)Ku_{n+1} - \alpha Ku_n = (1+\alpha)F_{n+1} - \alpha F_n",
        ascii="M*uddot_{n+1} + (1+alpha)*C*udot_{n+1} - alpha*C*udot_n + (1+alpha)*K*u_{n+1} - alpha*K*u_n = (1+alpha)*F_{n+1} - alpha*F_n",
        method="Hilber-Hughes-Taylor alpha method. Numerical damping for high frequencies while maintaining 2nd order accuracy.",
        reference="Hilber, Hughes & Taylor (1977); alpha in [-1/3, 0]",
        parameters={
            "alpha": "[-1/3, 0], typically -0.05",
            "beta": "(1-alpha)^2/4",
            "gamma": "(1-2*alpha)/2",
        },
    ),

    "runge_kutta_4": FormulaInfo(
        algorithm="Runge-Kutta 4th Order (RK4)",
        latex=r"\begin{aligned} k_1 &= f(t_n, y_n) \\ k_2 &= f(t_n+h/2,\, y_n+hk_1/2) \\ k_3 &= f(t_n+h/2,\, y_n+hk_2/2) \\ k_4 &= f(t_n+h,\, y_n+hk_3) \\ y_{n+1} &= y_n + \tfrac{h}{6}(k_1 + 2k_2 + 2k_3 + k_4) \end{aligned}",
        ascii="k1=f(t,y); k2=f(t+h/2,y+h*k1/2); k3=f(t+h/2,y+h*k2/2); k4=f(t+h,y+h*k3); y+=h/6*(k1+2k2+2k3+k4)",
        method="Classical 4th order Runge-Kutta. 4 function evaluations per step, O(h^4) local error.",
        reference="Butcher, 'Numerical Methods for ODEs', Ch.3",
        parameters={"order": "4", "stages": "4", "local_error": "O(h^5)"},
    ),

    # ==================================================================
    # CFD / TURBULENCE MODELS
    # ==================================================================

    "k_epsilon": FormulaInfo(
        algorithm="k-epsilon Turbulence Model",
        latex=r"\begin{aligned} \frac{\partial k}{\partial t} + U_j\frac{\partial k}{\partial x_j} &= P_k - \varepsilon + \frac{\partial}{\partial x_j}\left[\left(\nu + \frac{\nu_t}{\sigma_k}\right)\frac{\partial k}{\partial x_j}\right] \\ \frac{\partial \varepsilon}{\partial t} + U_j\frac{\partial \varepsilon}{\partial x_j} &= C_{\varepsilon 1}\frac{\varepsilon}{k}P_k - C_{\varepsilon 2}\frac{\varepsilon^2}{k} + \frac{\partial}{\partial x_j}\left[\left(\nu + \frac{\nu_t}{\sigma_\varepsilon}\right)\frac{\partial \varepsilon}{\partial x_j}\right] \end{aligned}",
        ascii="dk/dt + U*dk/dx = Pk - eps + d/dx[(nu+nu_t/sigma_k)*dk/dx]; deps/dt + U*deps/dx = Ce1*eps/k*Pk - Ce2*eps^2/k + d/dx[(nu+nu_t/sigma_eps)*deps/dx]",
        method="Standard k-epsilon RANS turbulence model. nu_t = C_mu * k^2 / epsilon.",
        reference="Launder & Spalding (1974); Wilcox, 'Turbulence Modeling for CFD', 3rd ed.",
        parameters={
            "C_mu": "0.09",
            "C_e1": "1.44",
            "C_e2": "1.92",
            "sigma_k": "1.0",
            "sigma_eps": "1.3",
        },
    ),

    "k_omega_sst": FormulaInfo(
        algorithm="k-omega SST",
        latex=r"\begin{aligned} \frac{\partial k}{\partial t} + U_j\frac{\partial k}{\partial x_j} &= \tilde{P}_k - \beta^* k\omega + \frac{\partial}{\partial x_j}\left[(\nu+\sigma_k\nu_t)\frac{\partial k}{\partial x_j}\right] \\ \frac{\partial \omega}{\partial t} + U_j\frac{\partial \omega}{\partial x_j} &= \frac{\gamma}{\nu_t}P_k - \beta\omega^2 + \frac{\partial}{\partial x_j}\left[(\nu+\sigma_\omega\nu_t)\frac{\partial \omega}{\partial x_j}\right] + 2(1-F_1)\frac{\sigma_{\omega 2}}{\omega}\frac{\partial k}{\partial x_j}\frac{\partial \omega}{\partial x_j} \end{aligned}",
        ascii="dk/dt + U*dk/dx = Pk_tilde - beta*k*omega + diff; domega/dt + U*domega/dx = gamma/nu_t*Pk - beta*omega^2 + diff + cross_diff",
        method="Menter's Shear Stress Transport model. Blends k-omega (near wall) and k-epsilon (freestream) via F1.",
        reference="Menter (1994); Menter, Kuntz & Langtry (2003)",
        parameters={
            "beta_star": "0.09",
            "a1": "0.31",
            "sigma_k1": "0.85",
            "sigma_w1": "0.5",
            "sigma_k2": "1.0",
            "sigma_w2": "0.856",
        },
    ),

    # ==================================================================
    # FINANCE
    # ==================================================================

    "black_scholes": FormulaInfo(
        algorithm="Black-Scholes",
        latex=r"C = S_0 N(d_1) - K e^{-rT} N(d_2), \quad d_{1,2} = \frac{\ln(S_0/K) + (r \pm \sigma^2/2)T}{\sigma\sqrt{T}}",
        ascii="C = S0*N(d1) - K*exp(-rT)*N(d2); d1 = [ln(S0/K) + (r+sigma^2/2)*T] / (sigma*sqrt(T)); d2 = d1 - sigma*sqrt(T)",
        method="Black-Scholes-Merton European option pricing formula.",
        reference="Black & Scholes (1973); Hull, 'Options, Futures, and Other Derivatives', Ch.15",
        parameters={
            "S0": "spot price",
            "K": "strike price",
            "r": "risk-free rate",
            "sigma": "volatility",
            "T": "time to maturity",
        },
    ),

    "monte_carlo_sim": FormulaInfo(
        algorithm="Monte Carlo Simulation",
        latex=r"E[f(X)] \approx \frac{1}{N}\sum_{i=1}^{N} f(X_i), \quad \text{error} = O(1/\sqrt{N})",
        ascii="E[f(X)] ~ (1/N) * sum(f(X_i)), error = O(1/sqrt(N))",
        method="Monte Carlo integration/simulation. Convergence independent of dimension.",
        reference="Glasserman, 'Monte Carlo Methods in Financial Engineering' (2003)",
        parameters={"convergence": "O(1/sqrt(N))", "variance_reduction": "antithetic, control variates, importance sampling"},
    ),

    "greeks_finite_diff": FormulaInfo(
        algorithm="Greeks (Finite Difference)",
        latex=r"\Delta = \frac{\partial V}{\partial S} \approx \frac{V(S+h) - V(S-h)}{2h}, \quad \Gamma = \frac{\partial^2 V}{\partial S^2} \approx \frac{V(S+h) - 2V(S) + V(S-h)}{h^2}",
        ascii="Delta = dV/dS ~ [V(S+h)-V(S-h)]/(2h); Gamma = d2V/dS2 ~ [V(S+h)-2V(S)+V(S-h)]/h^2",
        method="Finite difference computation of option Greeks (sensitivities).",
        reference="Hull, 'Options, Futures, and Other Derivatives', Ch.19",
        parameters={"delta": "dV/dS", "gamma": "d2V/dS2", "theta": "dV/dt", "vega": "dV/dsigma", "rho": "dV/dr"},
    ),

    # ==================================================================
    # MACHINE LEARNING
    # ==================================================================

    "gradient_descent": FormulaInfo(
        algorithm="Gradient Descent",
        latex=r"\theta_{t+1} = \theta_t - \eta \nabla_\theta \mathcal{L}(\theta_t)",
        ascii="theta_{t+1} = theta_t - lr * grad(L(theta_t))",
        method="Vanilla gradient descent. Step size (learning rate) eta controls convergence.",
        reference="Cauchy (1847); Ruder, 'An overview of gradient descent optimization algorithms' (2016)",
        parameters={"learning_rate": "0.001..0.1", "convergence": "O(1/T) for convex"},
    ),

    "adam_optimizer": FormulaInfo(
        algorithm="Adam Optimizer",
        latex=r"\begin{aligned} m_t &= \beta_1 m_{t-1} + (1-\beta_1)g_t \\ v_t &= \beta_2 v_{t-1} + (1-\beta_2)g_t^2 \\ \hat{m}_t &= m_t/(1-\beta_1^t), \quad \hat{v}_t = v_t/(1-\beta_2^t) \\ \theta_{t+1} &= \theta_t - \eta\,\hat{m}_t / (\sqrt{\hat{v}_t}+\epsilon) \end{aligned}",
        ascii="m=beta1*m+(1-beta1)*g; v=beta2*v+(1-beta2)*g^2; m_hat=m/(1-beta1^t); v_hat=v/(1-beta2^t); theta-=lr*m_hat/(sqrt(v_hat)+eps)",
        method="Adaptive Moment Estimation. Combines momentum (m) and RMSprop (v).",
        reference="Kingma & Ba (2015), 'Adam: A Method for Stochastic Optimization'",
        parameters={
            "beta1": "0.9",
            "beta2": "0.999",
            "epsilon": "1e-8",
            "learning_rate": "0.001",
        },
    ),

    "sgd_momentum": FormulaInfo(
        algorithm="SGD with Momentum",
        latex=r"v_t = \gamma v_{t-1} + \eta \nabla_\theta \mathcal{L}, \quad \theta_{t+1} = \theta_t - v_t",
        ascii="v = gamma*v_prev + lr*grad(L); theta -= v",
        method="Stochastic Gradient Descent with momentum. Accelerates convergence in ravines.",
        reference="Polyak (1964); Sutskever et al. (2013)",
        parameters={"momentum": "0.9", "learning_rate": "0.01"},
    ),

    "softmax": FormulaInfo(
        algorithm="Softmax",
        latex=r"\text{softmax}(z_i) = \frac{e^{z_i}}{\sum_{j=1}^{K} e^{z_j}}",
        ascii="softmax(z_i) = exp(z_i) / sum(exp(z_j))",
        method="Softmax activation function. Normalizes logits to probability distribution.",
        reference="Goodfellow et al., 'Deep Learning' (2016), Ch.6",
    ),

    "relu": FormulaInfo(
        algorithm="ReLU",
        latex=r"\text{ReLU}(x) = \max(0, x)",
        ascii="ReLU(x) = max(0, x)",
        method="Rectified Linear Unit. Default activation for hidden layers.",
        reference="Nair & Hinton (2010), 'Rectified Linear Units Improve RBMs'",
    ),

    "sigmoid": FormulaInfo(
        algorithm="Sigmoid",
        latex=r"\sigma(x) = \frac{1}{1 + e^{-x}}",
        ascii="sigma(x) = 1 / (1 + exp(-x))",
        method="Sigmoid activation. Maps input to (0,1). Used in binary classification output.",
        reference="Goodfellow et al., 'Deep Learning' (2016), Ch.6",
    ),

    "batch_normalization": FormulaInfo(
        algorithm="Batch Normalization",
        latex=r"\hat{x}_i = \frac{x_i - \mu_B}{\sqrt{\sigma_B^2 + \epsilon}}, \quad y_i = \gamma \hat{x}_i + \beta",
        ascii="x_hat = (x - mu_batch) / sqrt(var_batch + eps); y = gamma*x_hat + beta",
        method="Batch normalization. Normalizes activations per mini-batch.",
        reference="Ioffe & Szegedy (2015), 'Batch Normalization'",
        parameters={"epsilon": "1e-5", "momentum": "0.1"},
    ),

    "cross_entropy_loss": FormulaInfo(
        algorithm="Cross-Entropy Loss",
        latex=r"\mathcal{L} = -\sum_{i=1}^{C} y_i \log(\hat{y}_i)",
        ascii="L = -sum(y_i * log(y_hat_i))",
        method="Categorical cross-entropy loss for classification.",
        reference="Goodfellow et al., 'Deep Learning' (2016), Ch.6",
    ),

    # ==================================================================
    # DSP / SIGNAL PROCESSING
    # ==================================================================

    "fft": FormulaInfo(
        algorithm="Fast Fourier Transform",
        latex=r"X_k = \sum_{n=0}^{N-1} x_n \, e^{-i2\pi kn/N}, \quad k = 0,\ldots,N-1",
        ascii="X[k] = sum(x[n] * exp(-i*2*pi*k*n/N), n=0..N-1)",
        method="Cooley-Tukey FFT. O(N log N) vs O(N^2) for DFT.",
        reference="Cooley & Tukey (1965); Oppenheim & Schafer, 'Discrete-Time Signal Processing'",
        parameters={"complexity": "O(N*log(N))", "radix": "2 (most common)"},
    ),

    "convolution_1d": FormulaInfo(
        algorithm="Convolution (1D)",
        latex=r"(f * g)[n] = \sum_{k=-\infty}^{\infty} f[k]\,g[n-k]",
        ascii="(f*g)[n] = sum(f[k]*g[n-k])",
        method="Discrete convolution. Implemented via FFT for large signals (O(N log N)).",
        reference="Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.2",
    ),

    "fir_filter": FormulaInfo(
        algorithm="FIR Filter",
        latex=r"y[n] = \sum_{k=0}^{M} b_k\,x[n-k]",
        ascii="y[n] = sum(b[k]*x[n-k], k=0..M)",
        method="Finite Impulse Response filter. Always stable, linear phase possible.",
        reference="Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.7",
        parameters={"order": "M (number of taps - 1)", "phase": "linear if symmetric coefficients"},
    ),

    "iir_filter": FormulaInfo(
        algorithm="IIR Filter",
        latex=r"y[n] = \sum_{k=0}^{M} b_k\,x[n-k] - \sum_{k=1}^{N} a_k\,y[n-k]",
        ascii="y[n] = sum(b[k]*x[n-k]) - sum(a[k]*y[n-k])",
        method="Infinite Impulse Response filter. Recursive. Sharper rolloff than FIR for same order.",
        reference="Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.7",
        parameters={"types": "Butterworth, Chebyshev, Elliptic, Bessel"},
    ),

    "butterworth_filter": FormulaInfo(
        algorithm="Butterworth Filter",
        latex=r"|H(j\omega)|^2 = \frac{1}{1 + (\omega/\omega_c)^{2N}}",
        ascii="|H(jw)|^2 = 1 / (1 + (w/wc)^(2N))",
        method="Butterworth filter: maximally flat magnitude response in passband.",
        reference="Butterworth (1930); Oppenheim & Schafer, Ch.7",
        parameters={"order": "N", "cutoff": "omega_c"},
    ),

    "hamming_window": FormulaInfo(
        algorithm="Hamming Window",
        latex=r"w[n] = 0.54 - 0.46\cos\!\left(\frac{2\pi n}{N-1}\right)",
        ascii="w[n] = 0.54 - 0.46*cos(2*pi*n/(N-1))",
        method="Hamming window for spectral analysis. Reduces spectral leakage.",
        reference="Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.7",
    ),

    "hanning_window": FormulaInfo(
        algorithm="Hanning Window",
        latex=r"w[n] = 0.5\left(1 - \cos\!\left(\frac{2\pi n}{N-1}\right)\right)",
        ascii="w[n] = 0.5*(1 - cos(2*pi*n/(N-1)))",
        method="Hanning (von Hann) window. Smoother sidelobe decay than Hamming.",
        reference="Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.7",
    ),

    "blackman_window": FormulaInfo(
        algorithm="Blackman Window",
        latex=r"w[n] = 0.42 - 0.5\cos\!\left(\frac{2\pi n}{N-1}\right) + 0.08\cos\!\left(\frac{4\pi n}{N-1}\right)",
        ascii="w[n] = 0.42 - 0.5*cos(2*pi*n/(N-1)) + 0.08*cos(4*pi*n/(N-1))",
        method="Blackman window. Better sidelobe suppression (-58 dB) than Hamming/Hanning.",
        reference="Blackman & Tukey (1958)",
    ),

    # ==================================================================
    # LINEAR ALGEBRA
    # ==================================================================

    "svd": FormulaInfo(
        algorithm="Singular Value Decomposition",
        latex=r"A = U \Sigma V^T, \quad \Sigma = \text{diag}(\sigma_1 \geq \sigma_2 \geq \cdots \geq 0)",
        ascii="A = U * Sigma * V^T, Sigma = diag(sigma_1 >= sigma_2 >= ... >= 0)",
        method="SVD: fundamental matrix decomposition. Used in PCA, pseudoinverse, rank determination.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.2.5, Ch.8",
        parameters={"complexity": "O(mn*min(m,n))", "applications": "PCA, least squares, rank"},
    ),

    "sparse_cg_solve": FormulaInfo(
        algorithm="Sparse Matrix CG Solve",
        latex=r"Ax = b, \quad A \in \mathbb{R}^{n \times n} \text{ sparse SPD}, \quad \text{CG with } M^{-1} \approx A^{-1}",
        ascii="Ax=b, A sparse SPD; CG iterations with preconditioner M^{-1}",
        method="Conjugate Gradient for sparse SPD systems. Typically with ILU(0) or ICC preconditioner.",
        reference="Saad, 'Iterative Methods for Sparse Linear Systems', Ch.10",
        parameters={"storage": "CSR/CSC/COO", "preconditioner": "ILU(0), ICC, AMG"},
    ),

    # ==================================================================
    # ADDITIONAL ALGORITHMS
    # ==================================================================

    "galerkin_fem": FormulaInfo(
        algorithm="Galerkin FEM",
        latex=r"\int_\Omega \nabla w \cdot \nabla u\,d\Omega = \int_\Omega w\,f\,d\Omega + \int_{\Gamma_N} w\,g\,d\Gamma",
        ascii="int(grad(w).grad(u))dOmega = int(w*f)dOmega + int(w*g)dGamma",
        method="Standard Galerkin weak form. Basis functions serve as both trial and test functions.",
        reference="Zienkiewicz, Taylor & Zhu, 'The Finite Element Method', 7th ed., Ch.3",
    ),

    "isoparametric_mapping": FormulaInfo(
        algorithm="Isoparametric Mapping",
        latex=r"x = \sum_i N_i(\xi,\eta)\,x_i, \quad J = \frac{\partial(x,y)}{\partial(\xi,\eta)}",
        ascii="x = sum(N_i(xi,eta)*x_i); J = d(x,y)/d(xi,eta) Jacobian",
        method="Isoparametric element mapping. Same shape functions for geometry and field.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.5",
    ),

    "von_mises_stress": FormulaInfo(
        algorithm="von Mises Stress",
        latex=r"\sigma_\text{VM} = \sqrt{\sigma_1^2 - \sigma_1\sigma_2 + \sigma_2^2 + 3\tau_{12}^2}",
        ascii="sigma_VM = sqrt(s1^2 - s1*s2 + s2^2 + 3*tau12^2)",
        method="von Mises equivalent stress for yield criterion (plane stress).",
        reference="von Mises (1913); Boresi & Schmidt, 'Advanced Mechanics of Materials'",
    ),

    "geometric_brownian_motion": FormulaInfo(
        algorithm="Geometric Brownian Motion",
        latex=r"dS = \mu S\,dt + \sigma S\,dW_t, \quad S(T) = S_0 \exp\!\left[(\mu - \sigma^2/2)T + \sigma W_T\right]",
        ascii="dS = mu*S*dt + sigma*S*dW; S(T) = S0*exp[(mu-sigma^2/2)*T + sigma*W(T)]",
        method="GBM: standard model for stock price dynamics.",
        reference="Hull, 'Options, Futures, and Other Derivatives', Ch.14",
    ),

    "value_at_risk": FormulaInfo(
        algorithm="Value at Risk (VaR)",
        latex=r"\text{VaR}_\alpha = -\inf\{x : P(L \leq x) \geq \alpha\}",
        ascii="VaR_alpha = -inf{x : P(L <= x) >= alpha}",
        method="Value at Risk: maximum loss at confidence level alpha (typically 95% or 99%).",
        reference="Jorion, 'Value at Risk', 3rd ed.",
        parameters={"confidence": "95% or 99%", "horizon": "1 day or 10 days"},
    ),

    "leaky_relu": FormulaInfo(
        algorithm="Leaky ReLU",
        latex=r"\text{LeakyReLU}(x) = \begin{cases} x & x > 0 \\ \alpha x & x \leq 0 \end{cases}",
        ascii="LeakyReLU(x) = x if x>0 else alpha*x",
        method="Leaky ReLU. Avoids dying ReLU problem with small negative slope.",
        reference="Maas et al. (2013), 'Rectifier Nonlinearities'",
        parameters={"alpha": "0.01 (default)"},
    ),

    "tanh_activation": FormulaInfo(
        algorithm="Tanh Activation",
        latex=r"\tanh(x) = \frac{e^x - e^{-x}}{e^x + e^{-x}}",
        ascii="tanh(x) = (exp(x) - exp(-x)) / (exp(x) + exp(-x))",
        method="Hyperbolic tangent activation. Output in (-1, 1). Zero-centered.",
        reference="Goodfellow et al., 'Deep Learning' (2016), Ch.6",
    ),

    "gelu_activation": FormulaInfo(
        algorithm="GELU Activation",
        latex=r"\text{GELU}(x) = x \cdot \Phi(x) \approx 0.5\,x\left(1 + \tanh\!\left[\sqrt{2/\pi}(x + 0.044715\,x^3)\right]\right)",
        ascii="GELU(x) ~ 0.5*x*(1 + tanh(sqrt(2/pi)*(x + 0.044715*x^3)))",
        method="Gaussian Error Linear Unit. Default activation in Transformers (BERT, GPT).",
        reference="Hendrycks & Gimpel (2016), 'Gaussian Error Linear Units'",
    ),

    "layer_normalization": FormulaInfo(
        algorithm="Layer Normalization",
        latex=r"\hat{x}_i = \frac{x_i - \mu}{\sqrt{\sigma^2 + \epsilon}}, \quad \mu = \frac{1}{H}\sum_i x_i",
        ascii="x_hat = (x - mean) / sqrt(var + eps); y = gamma*x_hat + beta",
        method="Layer normalization. Normalizes across features (not batch). Used in Transformers.",
        reference="Ba, Kiros & Hinton (2016), 'Layer Normalization'",
    ),

    "attention_mechanism": FormulaInfo(
        algorithm="Scaled Dot-Product Attention",
        latex=r"\text{Attention}(Q,K,V) = \text{softmax}\!\left(\frac{QK^T}{\sqrt{d_k}}\right)V",
        ascii="Attention(Q,K,V) = softmax(Q*K^T / sqrt(d_k)) * V",
        method="Scaled dot-product attention. Core of Transformer architecture.",
        reference="Vaswani et al. (2017), 'Attention Is All You Need'",
        parameters={"d_k": "key dimension", "heads": "typically 8 or 12"},
    ),

    "upwind_scheme": FormulaInfo(
        algorithm="Upwind Scheme",
        latex=r"\frac{\partial u}{\partial t} + a\frac{\partial u}{\partial x} = 0: \quad u_i^{n+1} = u_i^n - \frac{a\Delta t}{\Delta x}(u_i^n - u_{i-1}^n) \quad (a>0)",
        ascii="u_i^{n+1} = u_i^n - a*dt/dx*(u_i - u_{i-1}) for a>0",
        method="First-order upwind scheme for advection. Stable but diffusive.",
        reference="Versteeg & Malalasekera, 'Intro to CFD', Ch.5",
    ),

    "central_difference": FormulaInfo(
        algorithm="Central Difference Scheme",
        latex=r"\frac{\partial u}{\partial x}\bigg|_i \approx \frac{u_{i+1} - u_{i-1}}{2\Delta x}",
        ascii="du/dx|_i ~ (u_{i+1} - u_{i-1}) / (2*dx)",
        method="Second-order central difference. Oscillatory for advection-dominated flows.",
        reference="Versteeg & Malalasekera, 'Intro to CFD', Ch.5",
    ),

    # ==================================================================
    # FEA CORE
    # ==================================================================

    "stiffness_matrix_assembly": FormulaInfo(
        algorithm="Stiffness Matrix Assembly",
        latex=r"K = \sum_e \int_{\Omega_e} B^T D B \, \det(J) \, d\xi = \sum_e \sum_q B^T(\xi_q) D B(\xi_q) \det(J_q) w_q",
        ascii="K = sum_e sum_q B^T(xi_q) * D * B(xi_q) * det(J_q) * w_q",
        method="Element stiffness matrix assembly via numerical quadrature. B is strain-displacement, D is constitutive, J is Jacobian.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.4; Zienkiewicz et al., 7th ed., Ch.6",
        parameters={
            "B": "strain-displacement matrix (dN/dx)",
            "D": "constitutive (material) matrix",
            "J": "Jacobian of isoparametric mapping",
            "w_q": "quadrature weight",
        },
    ),

    "mass_matrix": FormulaInfo(
        algorithm="Consistent Mass Matrix",
        latex=r"M = \sum_e \int_{\Omega_e} \rho\, N^T N \, \det(J) \, d\xi = \sum_e \sum_q \rho\, N^T(\xi_q) N(\xi_q) \det(J_q) w_q",
        ascii="M = sum_e sum_q rho * N^T(xi_q) * N(xi_q) * det(J_q) * w_q",
        method="Consistent mass matrix via numerical quadrature. Full coupling between DOFs (not lumped).",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.4",
        parameters={
            "rho": "material density",
            "N": "shape function matrix",
            "lumped_alternative": "M_L = diag(row_sum(M))",
        },
    ),

    "consistent_load_vector": FormulaInfo(
        algorithm="Consistent Load Vector",
        latex=r"f = \sum_e \int_{\Omega_e} N^T b \, \det(J) \, d\xi = \sum_e \sum_q N^T(\xi_q) b(\xi_q) \det(J_q) w_q",
        ascii="f = sum_e sum_q N^T(xi_q) * b(xi_q) * det(J_q) * w_q",
        method="Consistent nodal load vector from distributed body force b(x).",
        reference="Zienkiewicz, Taylor & Zhu, 'The Finite Element Method', 7th ed., Ch.3",
        parameters={"b": "body force vector", "N": "shape function matrix"},
    ),

    "jacobian_matrix": FormulaInfo(
        algorithm="Jacobian Matrix (FEA)",
        latex=r"J = \frac{\partial(x,y)}{\partial(\xi,\eta)} = \begin{bmatrix} \sum \frac{\partial N_i}{\partial \xi} x_i & \sum \frac{\partial N_i}{\partial \xi} y_i \\ \sum \frac{\partial N_i}{\partial \eta} x_i & \sum \frac{\partial N_i}{\partial \eta} y_i \end{bmatrix}",
        ascii="J = [[dN/dxi * x, dN/dxi * y], [dN/deta * x, dN/deta * y]]",
        method="Jacobian of isoparametric coordinate transformation. Maps parent to physical element.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.5",
        parameters={"det_J": "must be > 0 (valid mapping)", "inverse": "J^{-1} needed for B-matrix"},
    ),

    "b_matrix_strain_displacement": FormulaInfo(
        algorithm="B-Matrix (Strain-Displacement)",
        latex=r"B = L N, \quad \varepsilon = B u, \quad B_i = \begin{bmatrix} \frac{\partial N_i}{\partial x} & 0 \\ 0 & \frac{\partial N_i}{\partial y} \\ \frac{\partial N_i}{\partial y} & \frac{\partial N_i}{\partial x} \end{bmatrix}",
        ascii="B = L*N; epsilon = B*u; B_i = [[dNi/dx, 0], [0, dNi/dy], [dNi/dy, dNi/dx]]",
        method="Strain-displacement matrix. Relates nodal displacements to strains via shape function derivatives.",
        reference="Zienkiewicz, Taylor & Zhu, 'The Finite Element Method', 7th ed., Ch.6",
        parameters={"L": "differential operator matrix", "dN/dx": "computed via J^{-1} * dN/dxi"},
    ),

    "d_matrix_constitutive": FormulaInfo(
        algorithm="D-Matrix (Constitutive)",
        latex=r"\sigma = D \varepsilon, \quad D_\text{plane stress} = \frac{E}{1-\nu^2}\begin{bmatrix} 1 & \nu & 0 \\ \nu & 1 & 0 \\ 0 & 0 & \frac{1-\nu}{2} \end{bmatrix}",
        ascii="sigma = D * epsilon; D_ps = E/(1-nu^2) * [[1,nu,0],[nu,1,0],[0,0,(1-nu)/2]]",
        method="Constitutive (material stiffness) matrix. Links stress to strain for linear elastic material.",
        reference="Boresi & Schmidt, 'Advanced Mechanics of Materials', Ch.4",
        parameters={
            "E": "Young's modulus",
            "nu": "Poisson's ratio",
            "plane_stress": "thin plate assumption (sigma_z=0)",
            "plane_strain": "long body assumption (epsilon_z=0)",
        },
    ),

    "von_mises_yield": FormulaInfo(
        algorithm="von Mises Yield Criterion",
        latex=r"\sigma_\text{VM} = \sqrt{\frac{3}{2} s_{ij} s_{ij}} = \sqrt{\frac{1}{2}\left[(\sigma_1-\sigma_2)^2 + (\sigma_2-\sigma_3)^2 + (\sigma_3-\sigma_1)^2\right]} \leq \sigma_y",
        ascii="sigma_VM = sqrt(3/2 * s:s) = sqrt(1/2*[(s1-s2)^2+(s2-s3)^2+(s3-s1)^2]) <= sigma_y",
        method="von Mises yield criterion (J2 plasticity). Yield when equivalent stress reaches sigma_y.",
        reference="von Mises (1913); Simo & Hughes, 'Computational Inelasticity', Ch.2",
        parameters={
            "sigma_y": "yield stress",
            "s_ij": "deviatoric stress tensor (s = sigma - 1/3*tr(sigma)*I)",
            "J2": "second invariant of deviatoric stress",
        },
    ),

    "drucker_prager": FormulaInfo(
        algorithm="Drucker-Prager Yield Criterion",
        latex=r"f(\sigma) = \alpha I_1 + \sqrt{J_2} - k = 0, \quad I_1 = \text{tr}(\sigma), \; J_2 = \tfrac{1}{2}s_{ij}s_{ij}",
        ascii="f(sigma) = alpha*I1 + sqrt(J2) - k = 0; I1=tr(sigma), J2=1/2*s:s",
        method="Drucker-Prager yield criterion. Smooth approximation to Mohr-Coulomb for pressure-dependent materials.",
        reference="Drucker & Prager (1952); de Souza Neto et al., 'Computational Plasticity'",
        parameters={
            "alpha": "friction parameter = 2*sin(phi)/(sqrt(3)*(3-sin(phi)))",
            "k": "cohesion parameter = 6*c*cos(phi)/(sqrt(3)*(3-sin(phi)))",
            "phi": "friction angle",
            "c": "cohesion",
        },
    ),

    "mohr_coulomb": FormulaInfo(
        algorithm="Mohr-Coulomb Criterion",
        latex=r"\tau = c + \sigma_n \tan\phi, \quad \frac{\sigma_1 - \sigma_3}{2} = c\cos\phi + \frac{\sigma_1+\sigma_3}{2}\sin\phi",
        ascii="tau = c + sigma_n*tan(phi); (s1-s3)/2 = c*cos(phi) + (s1+s3)/2*sin(phi)",
        method="Mohr-Coulomb failure criterion. For soils, rocks, and frictional materials.",
        reference="Coulomb (1773); Chen & Han, 'Plasticity for Structural Engineers'",
        parameters={
            "c": "cohesion",
            "phi": "internal friction angle",
            "sigma_n": "normal stress on failure plane",
        },
    ),

    # ==================================================================
    # SOLVERS (additional)
    # ==================================================================

    "ilu_preconditioner": FormulaInfo(
        algorithm="Incomplete LU Factorization (ILU)",
        latex=r"A \approx \tilde{L}\tilde{U}, \quad \tilde{L}_{ij} = 0 \text{ if } A_{ij}=0 \text{ and } i>j",
        ascii="A ~ L_tilde * U_tilde; L_ij = 0 where A_ij = 0 (sparsity pattern preserved)",
        method="ILU(0): approximate LU factorization preserving sparsity pattern. Used as preconditioner for Krylov methods.",
        reference="Saad, 'Iterative Methods for Sparse Linear Systems', Ch.10",
        parameters={
            "ILU(0)": "same sparsity as A",
            "ILU(k)": "level-k fill-in allowed",
            "ILUT": "threshold-based drop tolerance",
        },
    ),

    "multigrid": FormulaInfo(
        algorithm="Multigrid Method",
        latex=r"\text{V-cycle: } \nu_1 \text{ pre-smooth} \to r^H = I_h^H(b-Ax) \to \text{coarse solve} \to u \mathrel{+}= I_H^h e^H \to \nu_2 \text{ post-smooth}",
        ascii="V-cycle: smooth(nu1) -> restrict(r) -> coarse_solve -> prolongate(e) -> smooth(nu2)",
        method="Geometric/algebraic multigrid. O(N) complexity for elliptic PDEs. Restriction + smoothing + prolongation.",
        reference="Briggs et al., 'A Multigrid Tutorial', 2nd ed.; Trottenberg et al., 'Multigrid'",
        parameters={
            "smoother": "Gauss-Seidel, Jacobi, SOR",
            "cycles": "V-cycle, W-cycle, F-cycle",
            "complexity": "O(N) optimal",
            "nu1": "pre-smoothing steps (1-3)",
            "nu2": "post-smoothing steps (1-3)",
        },
    ),

    "arc_length_riks": FormulaInfo(
        algorithm="Arc-Length Method (Riks)",
        latex=r"\begin{aligned} K \Delta u &= \lambda \hat{f} - f_\text{int} \\ \Delta u^T \Delta u + \Delta\lambda^2 \hat{f}^T \hat{f} &= \Delta l^2 \end{aligned}",
        ascii="K*du = lambda*f_hat - f_int; du^T*du + dlambda^2*f_hat^T*f_hat = dl^2 (constraint)",
        method="Riks/Crisfield arc-length method. Traces load-displacement path including snap-through and snap-back.",
        reference="Riks (1979); Crisfield (1981); de Borst et al., 'Non-linear FEA'",
        parameters={
            "dl": "arc-length increment",
            "lambda": "load parameter",
            "constraint": "spherical (Crisfield) or cylindrical",
        },
    ),

    "line_search_armijo": FormulaInfo(
        algorithm="Line Search (Armijo)",
        latex=r"f(x_k + \alpha_k d_k) \leq f(x_k) + c_1 \alpha_k \nabla f(x_k)^T d_k, \quad c_1 \in (0,1)",
        ascii="f(x + alpha*d) <= f(x) + c1*alpha*grad(f)^T*d (sufficient decrease)",
        method="Armijo backtracking line search. Ensures sufficient decrease in objective function.",
        reference="Armijo (1966); Nocedal & Wright, 'Numerical Optimization', Ch.3",
        parameters={
            "c1": "sufficient decrease parameter (1e-4)",
            "rho": "backtracking factor (0.5)",
            "alpha_init": "initial step size (1.0)",
        },
    ),

    # ==================================================================
    # TIME INTEGRATION (additional)
    # ==================================================================

    "explicit_central_difference": FormulaInfo(
        algorithm="Explicit Central Difference",
        latex=r"M \ddot{u}_n = F_n - C\dot{u}_n - Ku_n, \quad u_{n+1} = 2u_n - u_{n-1} + \Delta t^2 M^{-1}(F_n - Ku_n)",
        ascii="u_{n+1} = 2*u_n - u_{n-1} + dt^2 * M^{-1} * (F_n - K*u_n)",
        method="Explicit central difference time integration. Conditionally stable: dt <= 2/omega_max.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.9; Hughes, 'The FEM', Ch.9",
        parameters={
            "stability": "dt <= 2/omega_max (CFL condition)",
            "order": "2nd order accurate",
            "advantage": "no system solve needed (diagonal M)",
        },
    ),

    "bathe_method": FormulaInfo(
        algorithm="Bathe Time Integration",
        latex=r"\text{Sub-step 1 (trapezoidal):}\; u_{n+1/2} \quad \text{Sub-step 2 (3-point Euler backward):}\; u_{n+1}",
        ascii="Sub-step 1: trapezoidal rule [t_n, t_n+dt/2]; Sub-step 2: 3-point backward Euler [t_n+dt/2, t_n+dt]",
        method="Bathe composite method. Two sub-steps: trapezoidal + 3-point backward Euler. Unconditionally stable with controlled numerical dissipation.",
        reference="Bathe (2007), 'Conserving energy and momentum in nonlinear dynamics'",
        parameters={
            "sub_steps": "2",
            "stability": "unconditionally stable",
            "dissipation": "controllable high-frequency damping",
        },
    ),

    "generalized_alpha": FormulaInfo(
        algorithm="Generalized-Alpha Method",
        latex=r"\begin{aligned} M\ddot{u}_{n+1-\alpha_m} + C\dot{u}_{n+1-\alpha_f} + Ku_{n+1-\alpha_f} &= F_{n+1-\alpha_f} \\ \ddot{u}_{n+1-\alpha_m} &= (1-\alpha_m)\ddot{u}_{n+1} + \alpha_m\ddot{u}_n \end{aligned}",
        ascii="M*uddot_{n+1-am} + C*udot_{n+1-af} + K*u_{n+1-af} = F_{n+1-af}; weighted avg with alpha_m, alpha_f",
        method="Generalized-alpha method. User-controlled numerical dissipation via spectral radius rho_inf.",
        reference="Chung & Hulbert (1993); Jansen et al. (2000) for fluid dynamics",
        parameters={
            "alpha_m": "(2*rho_inf - 1)/(rho_inf + 1)",
            "alpha_f": "rho_inf/(rho_inf + 1)",
            "rho_inf": "spectral radius at infinity [0,1]",
            "order": "2nd order accurate",
        },
    ),

    "bdf_multistep": FormulaInfo(
        algorithm="Backward Differentiation Formula (BDF)",
        latex=r"\text{BDF-}k: \sum_{j=0}^{k} \alpha_j y_{n+1-j} = h \beta_0 f(t_{n+1}, y_{n+1})",
        ascii="BDF-k: sum(alpha_j * y_{n+1-j}) = h * beta_0 * f(t_{n+1}, y_{n+1}); BDF-2: 3/2*y_{n+1} - 2*y_n + 1/2*y_{n-1} = h*f_{n+1}",
        method="BDF multistep methods for stiff ODEs. A-stable for k<=2, A(alpha)-stable for k<=6.",
        reference="Gear (1971); Hairer & Wanner, 'Solving ODEs II: Stiff and DAE Problems'",
        parameters={
            "BDF-1": "backward Euler (1st order)",
            "BDF-2": "3/2*y_{n+1} - 2*y_n + 1/2*y_{n-1} = h*f_{n+1}",
            "max_order": "6 (unstable for k>6)",
        },
    ),

    # ==================================================================
    # CFD (additional)
    # ==================================================================

    "navier_stokes_incompressible": FormulaInfo(
        algorithm="Navier-Stokes (Incompressible)",
        latex=r"\begin{aligned} \rho\left(\frac{\partial \mathbf{u}}{\partial t} + (\mathbf{u}\cdot\nabla)\mathbf{u}\right) &= -\nabla p + \mu\nabla^2\mathbf{u} + \mathbf{f} \\ \nabla\cdot\mathbf{u} &= 0 \end{aligned}",
        ascii="rho*(du/dt + (u.grad)u) = -grad(p) + mu*laplacian(u) + f; div(u) = 0",
        method="Incompressible Navier-Stokes equations. Momentum + continuity (divergence-free constraint).",
        reference="Batchelor, 'An Introduction to Fluid Dynamics'; Ferziger & Peric, 'Computational Methods for Fluid Dynamics'",
        parameters={
            "rho": "density (constant for incompressible)",
            "mu": "dynamic viscosity",
            "nu": "kinematic viscosity = mu/rho",
            "Re": "Reynolds number = U*L/nu",
        },
    ),

    "simple_algorithm": FormulaInfo(
        algorithm="SIMPLE Algorithm",
        latex=r"\begin{aligned} A_P u_P^* &= \sum A_{nb} u_{nb}^* + (p_n^* - p_s^*) \Delta y \\ \nabla^2 p' &= -\frac{\rho}{\Delta t}\nabla\cdot\mathbf{u}^* \\ p &= p^* + \alpha_p p', \quad \mathbf{u} = \mathbf{u}^* - \frac{\Delta t}{\rho}\nabla p' \end{aligned}",
        ascii="Solve u* with guessed p*; solve pressure correction p'; update p=p*+alpha_p*p'; correct u=u*-dt/rho*grad(p')",
        method="Semi-Implicit Method for Pressure-Linked Equations. Iterative pressure-velocity coupling for incompressible flow.",
        reference="Patankar & Spalding (1972); Patankar, 'Numerical Heat Transfer and Fluid Flow'",
        parameters={
            "alpha_p": "pressure under-relaxation (0.3)",
            "alpha_u": "velocity under-relaxation (0.7)",
            "iterations": "outer loop until convergence",
        },
    ),

    "piso_algorithm": FormulaInfo(
        algorithm="PISO Algorithm",
        latex=r"\text{Predictor: } u^* \to \text{Corrector 1: } p',u^{**} \to \text{Corrector 2: } p'',u^{***}",
        ascii="Predictor: solve momentum -> u*; Corrector 1: pressure correction p' -> u**; Corrector 2: p'' -> u***",
        method="Pressure Implicit with Splitting of Operators. Non-iterative pressure-velocity coupling (2 corrections per timestep).",
        reference="Issa (1986); Versteeg & Malalasekera, 'Intro to CFD', Ch.6",
        parameters={
            "corrector_steps": "2 (standard PISO)",
            "advantage": "no outer iterations needed per timestep",
        },
    ),

    "boussinesq_approximation": FormulaInfo(
        algorithm="Boussinesq Approximation",
        latex=r"\rho = \rho_0\left[1 - \beta(T - T_0)\right], \quad \mathbf{f}_\text{buoyancy} = -\rho_0 \beta (T-T_0)\mathbf{g}",
        ascii="rho = rho_0*(1 - beta*(T-T0)); f_buoyancy = -rho_0*beta*(T-T0)*g",
        method="Boussinesq approximation for buoyancy-driven flows. Density variations only in gravity term.",
        reference="Boussinesq (1903); Bejan, 'Convection Heat Transfer', 4th ed.",
        parameters={
            "beta": "thermal expansion coefficient (1/K)",
            "T0": "reference temperature",
            "rho_0": "reference density",
            "Ra": "Rayleigh number = g*beta*dT*L^3/(nu*alpha)",
        },
    ),

    "fractional_step_method": FormulaInfo(
        algorithm="Fractional Step Method",
        latex=r"\begin{aligned} \frac{\mathbf{u}^* - \mathbf{u}^n}{\Delta t} &= -(\mathbf{u}^n\cdot\nabla)\mathbf{u}^n + \nu\nabla^2\mathbf{u}^n \\ \nabla^2 p^{n+1} &= \frac{\rho}{\Delta t}\nabla\cdot\mathbf{u}^* \\ \mathbf{u}^{n+1} &= \mathbf{u}^* - \frac{\Delta t}{\rho}\nabla p^{n+1} \end{aligned}",
        ascii="Step 1: u* = u_n + dt*(-u.grad(u) + nu*laplacian(u)); Step 2: laplacian(p) = rho/dt*div(u*); Step 3: u_{n+1} = u* - dt/rho*grad(p)",
        method="Chorin's projection/fractional step method. Splits momentum and pressure for incompressible NS.",
        reference="Chorin (1968); Kim & Moin (1985)",
        parameters={
            "step_1": "advection-diffusion (explicit or implicit)",
            "step_2": "pressure Poisson equation",
            "step_3": "velocity correction (projection)",
        },
    ),

    # ==================================================================
    # STRUCTURAL MECHANICS
    # ==================================================================

    "euler_bernoulli_beam": FormulaInfo(
        algorithm="Euler-Bernoulli Beam",
        latex=r"EI\frac{d^4 w}{dx^4} = q(x), \quad M = -EI\frac{d^2 w}{dx^2}, \quad V = -EI\frac{d^3 w}{dx^3}",
        ascii="EI*d4w/dx4 = q(x); M = -EI*d2w/dx2; V = -EI*d3w/dx3",
        method="Euler-Bernoulli beam theory. Plane sections remain plane and normal to neutral axis (no shear deformation).",
        reference="Timoshenko & Gere, 'Mechanics of Materials'; Cook et al., 'Concepts and Applications of FEA'",
        parameters={
            "E": "Young's modulus",
            "I": "second moment of area",
            "w": "transverse deflection",
            "q": "distributed load",
            "validity": "L/h > 10 (slender beams)",
        },
    ),

    "timoshenko_beam": FormulaInfo(
        algorithm="Timoshenko Beam",
        latex=r"\begin{aligned} GA_s\left(\frac{dw}{dx} - \theta\right)' + q &= 0 \\ EI\theta'' + GA_s\left(\frac{dw}{dx} - \theta\right) &= 0 \end{aligned}",
        ascii="GA_s*(dw/dx - theta)' + q = 0; EI*theta'' + GA_s*(dw/dx - theta) = 0",
        method="Timoshenko beam theory. Includes transverse shear deformation. Valid for thick beams (L/h < 10).",
        reference="Timoshenko (1921); Reddy, 'An Introduction to the FEM', 3rd ed.",
        parameters={
            "A_s": "shear area = kappa*A",
            "kappa": "shear correction factor (5/6 for rect, 0.9 for circular)",
            "theta": "rotation of cross-section",
        },
    ),

    "kirchhoff_plate": FormulaInfo(
        algorithm="Kirchhoff Plate Theory",
        latex=r"D\nabla^4 w = q, \quad D = \frac{Eh^3}{12(1-\nu^2)}, \quad \nabla^4 = \frac{\partial^4}{\partial x^4} + 2\frac{\partial^4}{\partial x^2\partial y^2} + \frac{\partial^4}{\partial y^4}",
        ascii="D*nabla4(w) = q; D = E*h^3/(12*(1-nu^2)); nabla4 = d4/dx4 + 2*d4/dx2dy2 + d4/dy4",
        method="Kirchhoff (thin) plate bending theory. No transverse shear deformation (analogous to Euler-Bernoulli for beams).",
        reference="Timoshenko & Woinowsky-Krieger, 'Theory of Plates and Shells'",
        parameters={
            "D": "flexural rigidity",
            "h": "plate thickness",
            "validity": "h/L < 1/20 (thin plate)",
        },
    ),

    "mindlin_reissner_plate": FormulaInfo(
        algorithm="Mindlin-Reissner Plate Theory",
        latex=r"\begin{aligned} D\nabla^2\theta_x + D\frac{1-\nu}{2}\nabla^2\theta_x + \kappa G h\left(\frac{\partial w}{\partial x} - \theta_x\right) &= 0 \\ \kappa G h\left(\nabla^2 w - \frac{\partial\theta_x}{\partial x} - \frac{\partial\theta_y}{\partial y}\right) + q &= 0 \end{aligned}",
        ascii="Kirchhoff + transverse shear: kappa*G*h*(laplacian(w) - div(theta)) + q = 0",
        method="Mindlin-Reissner (thick) plate theory. Includes transverse shear deformation. Analogous to Timoshenko for beams.",
        reference="Mindlin (1951); Reissner (1945); Hughes, 'The Finite Element Method'",
        parameters={
            "kappa": "shear correction factor (5/6)",
            "G": "shear modulus = E/(2*(1+nu))",
            "validity": "valid for both thin and thick plates",
        },
    ),

    "buckling_eigenvalue": FormulaInfo(
        algorithm="Linear Buckling Analysis",
        latex=r"(K + \lambda K_G)\phi = 0, \quad \det(K + \lambda K_G) = 0",
        ascii="(K + lambda*K_G)*phi = 0; det(K + lambda*K_G) = 0",
        method="Linear buckling eigenvalue problem. K is stiffness, K_G is geometric stiffness, lambda is critical load factor.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.6; Cook et al., 'Concepts and Applications of FEA'",
        parameters={
            "K": "elastic stiffness matrix",
            "K_G": "geometric stiffness (stress stiffness) matrix",
            "lambda": "critical load multiplier",
            "phi": "buckling mode shape",
        },
    ),

    "modal_analysis": FormulaInfo(
        algorithm="Modal Analysis (Free Vibration)",
        latex=r"(K - \omega^2 M)\phi = 0, \quad \det(K - \omega^2 M) = 0, \quad f_n = \frac{\omega_n}{2\pi}",
        ascii="(K - omega^2*M)*phi = 0; det(K - omega^2*M) = 0; f_n = omega_n/(2*pi)",
        method="Generalized eigenvalue problem for natural frequencies and mode shapes.",
        reference="Bathe, 'Finite Element Procedures', 2nd ed., Ch.10; Chopra, 'Dynamics of Structures'",
        parameters={
            "K": "stiffness matrix",
            "M": "mass matrix",
            "omega_n": "natural circular frequency",
            "phi_n": "mode shape vector",
        },
    ),

    # ==================================================================
    # HEAT TRANSFER
    # ==================================================================

    "fourier_law": FormulaInfo(
        algorithm="Fourier's Law of Heat Conduction",
        latex=r"\mathbf{q} = -k\nabla T, \quad q_x = -k\frac{\partial T}{\partial x}",
        ascii="q = -k*grad(T); q_x = -k*dT/dx",
        method="Fourier's law: heat flux proportional to negative temperature gradient.",
        reference="Incropera et al., 'Fundamentals of Heat and Mass Transfer', 7th ed., Ch.2",
        parameters={"k": "thermal conductivity (W/m*K)", "q": "heat flux (W/m^2)"},
    ),

    "heat_equation": FormulaInfo(
        algorithm="Heat Equation (Transient Conduction)",
        latex=r"\rho c_p \frac{\partial T}{\partial t} = \nabla\cdot(k\nabla T) + Q",
        ascii="rho*cp*dT/dt = div(k*grad(T)) + Q",
        method="Transient heat conduction equation with volumetric heat generation Q.",
        reference="Incropera et al., 'Fundamentals of Heat and Mass Transfer', 7th ed., Ch.5",
        parameters={
            "rho": "density",
            "cp": "specific heat capacity",
            "k": "thermal conductivity",
            "Q": "volumetric heat generation (W/m^3)",
            "alpha": "thermal diffusivity = k/(rho*cp)",
        },
    ),

    "newton_cooling": FormulaInfo(
        algorithm="Newton's Law of Cooling",
        latex=r"q = h(T_s - T_\infty), \quad \dot{Q} = hA(T_s - T_\infty)",
        ascii="q = h*(T_s - T_inf); Q_dot = h*A*(T_s - T_inf)",
        method="Newton's law of cooling for convective heat transfer at a surface.",
        reference="Incropera et al., 'Fundamentals of Heat and Mass Transfer', 7th ed., Ch.1",
        parameters={
            "h": "convective heat transfer coefficient (W/m^2*K)",
            "T_s": "surface temperature",
            "T_inf": "fluid temperature",
        },
    ),

    "stefan_boltzmann_radiation": FormulaInfo(
        algorithm="Stefan-Boltzmann Radiation",
        latex=r"q = \varepsilon\sigma(T_s^4 - T_\text{surr}^4), \quad \sigma = 5.670 \times 10^{-8}\;\text{W/m}^2\text{K}^4",
        ascii="q = epsilon*sigma*(T_s^4 - T_surr^4); sigma = 5.670e-8 W/(m^2*K^4)",
        method="Stefan-Boltzmann law for thermal radiation exchange.",
        reference="Incropera et al., 'Fundamentals of Heat and Mass Transfer', 7th ed., Ch.12",
        parameters={
            "epsilon": "surface emissivity (0-1)",
            "sigma": "Stefan-Boltzmann constant = 5.670e-8",
            "T": "absolute temperature (K)",
        },
    ),

    "convection_diffusion": FormulaInfo(
        algorithm="Convection-Diffusion Equation",
        latex=r"\frac{\partial T}{\partial t} + \mathbf{u}\cdot\nabla T = \alpha\nabla^2 T + S",
        ascii="dT/dt + u.grad(T) = alpha*laplacian(T) + S",
        method="Advection-diffusion equation for scalar transport (temperature, concentration).",
        reference="Patankar, 'Numerical Heat Transfer and Fluid Flow'; Versteeg & Malalasekera, Ch.5",
        parameters={
            "alpha": "diffusivity",
            "u": "velocity field",
            "Pe": "Peclet number = U*L/alpha",
            "S": "source term",
        },
    ),

    # ==================================================================
    # STATISTICS / PROBABILITY
    # ==================================================================

    "normal_distribution": FormulaInfo(
        algorithm="Normal (Gaussian) Distribution",
        latex=r"f(x) = \frac{1}{\sigma\sqrt{2\pi}} \exp\!\left(-\frac{(x-\mu)^2}{2\sigma^2}\right)",
        ascii="f(x) = 1/(sigma*sqrt(2*pi)) * exp(-(x-mu)^2 / (2*sigma^2))",
        method="Probability density function of the normal (Gaussian) distribution.",
        reference="Papoulis & Pillai, 'Probability, Random Variables, and Stochastic Processes', 4th ed.",
        parameters={
            "mu": "mean",
            "sigma": "standard deviation",
            "sigma^2": "variance",
            "68-95-99.7": "rule for 1,2,3 sigma",
        },
    ),

    "chi_squared_distribution": FormulaInfo(
        algorithm="Chi-Squared Distribution",
        latex=r"f(x; k) = \frac{x^{k/2-1} e^{-x/2}}{2^{k/2}\,\Gamma(k/2)}, \quad x \geq 0",
        ascii="f(x; k) = x^(k/2-1) * exp(-x/2) / (2^(k/2) * Gamma(k/2)), x >= 0",
        method="Chi-squared distribution with k degrees of freedom. Sum of k squared standard normals.",
        reference="DeGroot & Schervish, 'Probability and Statistics', 4th ed.",
        parameters={
            "k": "degrees of freedom",
            "mean": "k",
            "variance": "2k",
            "use": "goodness-of-fit test, confidence intervals for variance",
        },
    ),

    "student_t_distribution": FormulaInfo(
        algorithm="Student's t-Distribution",
        latex=r"f(t; \nu) = \frac{\Gamma((\nu+1)/2)}{\sqrt{\nu\pi}\,\Gamma(\nu/2)} \left(1 + \frac{t^2}{\nu}\right)^{-(\nu+1)/2}",
        ascii="f(t; nu) = Gamma((nu+1)/2) / (sqrt(nu*pi)*Gamma(nu/2)) * (1 + t^2/nu)^(-(nu+1)/2)",
        method="Student's t-distribution with nu degrees of freedom. Approaches normal as nu -> infinity.",
        reference="Student (W.S. Gosset, 1908); DeGroot & Schervish, 4th ed.",
        parameters={
            "nu": "degrees of freedom",
            "mean": "0 (for nu>1)",
            "variance": "nu/(nu-2) (for nu>2)",
            "use": "small-sample inference for mean",
        },
    ),

    "bayesian_update": FormulaInfo(
        algorithm="Bayesian Update (Bayes' Theorem)",
        latex=r"P(A|B) = \frac{P(B|A)\,P(A)}{P(B)} = \frac{P(B|A)\,P(A)}{\sum_i P(B|A_i)P(A_i)}",
        ascii="P(A|B) = P(B|A)*P(A) / P(B); posterior = likelihood * prior / evidence",
        method="Bayes' theorem for updating prior beliefs given evidence. Foundation of Bayesian inference.",
        reference="Gelman et al., 'Bayesian Data Analysis', 3rd ed.; Jaynes, 'Probability Theory'",
        parameters={
            "prior": "P(A) - belief before evidence",
            "likelihood": "P(B|A) - probability of evidence given hypothesis",
            "posterior": "P(A|B) - updated belief",
            "evidence": "P(B) - normalizing constant",
        },
    ),

    "maximum_likelihood": FormulaInfo(
        algorithm="Maximum Likelihood Estimation (MLE)",
        latex=r"\hat{\theta}_\text{MLE} = \arg\max_\theta \prod_{i=1}^{n} f(x_i|\theta) = \arg\max_\theta \sum_{i=1}^{n} \ln f(x_i|\theta)",
        ascii="theta_MLE = argmax prod(f(x_i|theta)) = argmax sum(ln(f(x_i|theta)))",
        method="Maximum likelihood estimation. Finds parameters that maximize the probability of observed data.",
        reference="Casella & Berger, 'Statistical Inference', 2nd ed., Ch.7",
        parameters={
            "log_likelihood": "l(theta) = sum(ln(f(x_i|theta)))",
            "score": "dl/dtheta = 0 (stationary point)",
            "fisher_info": "I(theta) = -E[d2l/dtheta2]",
            "asymptotic": "sqrt(n)*(theta_hat-theta) -> N(0, 1/I(theta))",
        },
    ),

    # ==================================================================
    # OPTIMIZATION
    # ==================================================================

    "lagrangian_optimization": FormulaInfo(
        algorithm="Lagrangian Optimization",
        latex=r"\mathcal{L}(x,\lambda) = f(x) + \lambda^T g(x), \quad \nabla_x \mathcal{L} = 0, \quad g(x) = 0",
        ascii="L(x,lambda) = f(x) + lambda^T * g(x); grad_x(L) = 0; g(x) = 0",
        method="Lagrangian method for equality-constrained optimization. Lambda are Lagrange multipliers.",
        reference="Nocedal & Wright, 'Numerical Optimization', 2nd ed., Ch.12",
        parameters={
            "f": "objective function",
            "g": "equality constraints g(x) = 0",
            "lambda": "Lagrange multipliers (shadow prices)",
        },
    ),

    "kkt_conditions": FormulaInfo(
        algorithm="Karush-Kuhn-Tucker (KKT) Conditions",
        latex=r"\begin{aligned} \nabla f + \sum \lambda_i \nabla g_i + \sum \mu_j \nabla h_j &= 0 \\ g_i(x) &= 0 \\ h_j(x) &\leq 0 \\ \mu_j &\geq 0, \quad \mu_j h_j(x) = 0 \end{aligned}",
        ascii="grad(f) + sum(lambda_i*grad(g_i)) + sum(mu_j*grad(h_j)) = 0; g_i=0; h_j<=0; mu_j>=0; mu_j*h_j=0",
        method="KKT necessary conditions for constrained optimization. Generalize Lagrangian to inequality constraints.",
        reference="Nocedal & Wright, 'Numerical Optimization', 2nd ed., Ch.12; Boyd & Vandenberghe, Ch.5",
        parameters={
            "stationarity": "grad(L) = 0",
            "primal_feasibility": "g=0, h<=0",
            "dual_feasibility": "mu >= 0",
            "complementary_slackness": "mu*h = 0",
        },
    ),

    "penalty_method": FormulaInfo(
        algorithm="Penalty Method",
        latex=r"\min_x \; f(x) + \frac{\mu}{2}\|g(x)\|^2, \quad \mu \to \infty",
        ascii="min f(x) + mu/2 * ||g(x)||^2; mu -> infinity",
        method="Penalty method: converts constrained problem to unconstrained by penalizing violations.",
        reference="Nocedal & Wright, 'Numerical Optimization', 2nd ed., Ch.17",
        parameters={
            "mu": "penalty parameter (increasing sequence)",
            "disadvantage": "ill-conditioning as mu -> inf",
        },
    ),

    "augmented_lagrangian": FormulaInfo(
        algorithm="Augmented Lagrangian Method",
        latex=r"\mathcal{L}_A(x,\lambda,\mu) = f(x) + \lambda^T g(x) + \frac{\mu}{2}\|g(x)\|^2",
        ascii="L_A(x,lambda,mu) = f(x) + lambda^T*g(x) + mu/2*||g(x)||^2",
        method="Augmented Lagrangian (method of multipliers). Combines Lagrangian and penalty. Better conditioning than pure penalty.",
        reference="Nocedal & Wright, 'Numerical Optimization', 2nd ed., Ch.17; Bertsekas, 'Constrained Optimization'",
        parameters={
            "lambda": "Lagrange multiplier estimate",
            "mu": "penalty parameter",
            "update": "lambda_{k+1} = lambda_k + mu*g(x_k)",
        },
    ),

    "interior_point": FormulaInfo(
        algorithm="Interior Point Method",
        latex=r"\min_x f(x) - \mu \sum_{j} \ln(-h_j(x)) \quad \text{s.t. } g(x) = 0, \quad \mu \to 0^+",
        ascii="min f(x) - mu*sum(ln(-h_j(x))) s.t. g(x)=0; mu -> 0+ (barrier function)",
        method="Interior point (barrier) method. Logarithmic barrier keeps iterates strictly feasible.",
        reference="Nocedal & Wright, 'Numerical Optimization', 2nd ed., Ch.19; Boyd & Vandenberghe, Ch.11",
        parameters={
            "mu": "barrier parameter (decreasing to 0)",
            "barrier": "-sum(ln(-h_j(x)))",
            "complexity": "polynomial time for LP/QP/SOCP/SDP",
        },
    ),

    # ==================================================================
    # FINANCE (extended)
    # ==================================================================

    "heston_model": FormulaInfo(
        algorithm="Heston Stochastic Volatility Model",
        latex=r"\begin{aligned} dS &= \mu S\,dt + \sqrt{v}\,S\,dW_1 \\ dv &= \kappa(\theta - v)\,dt + \xi\sqrt{v}\,dW_2 \\ \text{corr}(dW_1, dW_2) &= \rho \end{aligned}",
        ascii="dS = mu*S*dt + sqrt(v)*S*dW1; dv = kappa*(theta-v)*dt + xi*sqrt(v)*dW2; corr(dW1,dW2)=rho",
        method="Heston model: stochastic volatility. CIR process for variance. Semi-closed form for European options.",
        reference="Heston (1993), 'A Closed-Form Solution for Options with Stochastic Volatility'",
        parameters={
            "kappa": "mean reversion speed of variance",
            "theta": "long-run variance",
            "xi": "vol-of-vol (volatility of volatility)",
            "rho": "correlation between price and vol (-0.7 typical)",
            "Feller": "2*kappa*theta > xi^2 (ensures v>0)",
        },
    ),

    "vasicek_model": FormulaInfo(
        algorithm="Vasicek Interest Rate Model",
        latex=r"dr = a(b - r)\,dt + \sigma\,dW, \quad r(T) \sim N\!\left(b + (r_0-b)e^{-aT},\, \frac{\sigma^2}{2a}(1-e^{-2aT})\right)",
        ascii="dr = a*(b-r)*dt + sigma*dW; r(T) ~ N(b+(r0-b)*e^(-aT), sigma^2/(2a)*(1-e^(-2aT)))",
        method="Vasicek model: mean-reverting Ornstein-Uhlenbeck process for interest rates. Allows negative rates.",
        reference="Vasicek (1977), 'An Equilibrium Characterization of the Term Structure'",
        parameters={
            "a": "mean reversion speed",
            "b": "long-run mean rate",
            "sigma": "volatility",
            "drawback": "allows negative interest rates",
        },
    ),

    "cir_model": FormulaInfo(
        algorithm="Cox-Ingersoll-Ross (CIR) Model",
        latex=r"dr = a(b - r)\,dt + \sigma\sqrt{r}\,dW, \quad 2ab > \sigma^2 \text{ (Feller condition)}",
        ascii="dr = a*(b-r)*dt + sigma*sqrt(r)*dW; 2*a*b > sigma^2 (ensures r>0)",
        method="CIR model: mean-reverting short rate with non-negative rates. Square-root diffusion.",
        reference="Cox, Ingersoll & Ross (1985), 'A Theory of the Term Structure of Interest Rates'",
        parameters={
            "a": "mean reversion speed",
            "b": "long-run mean rate",
            "sigma": "volatility",
            "feller": "2*a*b > sigma^2 (non-negativity)",
        },
    ),

    "bond_pricing": FormulaInfo(
        algorithm="Bond Pricing (Discounted Cash Flow)",
        latex=r"P = \sum_{t=1}^{T} \frac{C}{(1+r)^t} + \frac{F}{(1+r)^T}",
        ascii="P = sum(C/(1+r)^t, t=1..T) + F/(1+r)^T",
        method="Bond pricing via discounted cash flows. Sum of PV of coupons plus PV of face value.",
        reference="Fabozzi, 'Fixed Income Analysis', 3rd ed.; Hull, Ch.4",
        parameters={
            "C": "coupon payment",
            "F": "face value (par)",
            "r": "yield to maturity (per period)",
            "T": "number of periods to maturity",
        },
    ),

    "duration_convexity": FormulaInfo(
        algorithm="Duration and Convexity",
        latex=r"\begin{aligned} D_\text{mac} &= \frac{1}{P}\sum_{t=1}^{T} \frac{t\,CF_t}{(1+y)^t} \\ D_\text{mod} &= \frac{D_\text{mac}}{1+y} \\ C &= \frac{1}{P}\sum_{t=1}^{T} \frac{t(t+1)\,CF_t}{(1+y)^{t+2}} \end{aligned}",
        ascii="D_mac = (1/P)*sum(t*CF_t/(1+y)^t); D_mod = D_mac/(1+y); Convexity = (1/P)*sum(t*(t+1)*CF_t/(1+y)^(t+2))",
        method="Duration measures interest rate sensitivity. Convexity captures curvature. dP/P ~ -D*dy + 0.5*C*dy^2.",
        reference="Fabozzi, 'Fixed Income Analysis', 3rd ed.",
        parameters={
            "D_mac": "Macaulay duration (weighted average time)",
            "D_mod": "modified duration = D_mac/(1+y)",
            "C": "convexity",
            "price_change": "dP/P ~ -D_mod*dy + 0.5*C*dy^2",
        },
    ),

    "markowitz_portfolio": FormulaInfo(
        algorithm="Markowitz Mean-Variance Portfolio",
        latex=r"\min_w \; w^T \Sigma w \quad \text{s.t.} \quad w^T \mu = r_\text{target}, \quad w^T \mathbf{1} = 1",
        ascii="min w^T*Sigma*w s.t. w^T*mu = r_target, w^T*1 = 1",
        method="Markowitz mean-variance optimization. Efficient frontier of risk-return trade-offs.",
        reference="Markowitz (1952), 'Portfolio Selection'; Markowitz (1959), 'Portfolio Selection: Efficient Diversification'",
        parameters={
            "w": "portfolio weight vector",
            "Sigma": "covariance matrix of returns",
            "mu": "expected return vector",
            "r_target": "target portfolio return",
        },
    ),

    # ==================================================================
    # NUMERICAL METHODS (additional)
    # ==================================================================

    "bisection_method": FormulaInfo(
        algorithm="Bisection Method",
        latex=r"c = \frac{a+b}{2}; \quad \text{if } f(a)f(c)<0: b=c, \quad \text{else } a=c",
        ascii="c = (a+b)/2; if f(a)*f(c)<0 then b=c else a=c; repeat until |b-a|<tol",
        method="Bisection root-finding. Guaranteed convergence for continuous f with sign change. Linear convergence.",
        reference="Burden & Faires, 'Numerical Analysis', 10th ed., Ch.2",
        parameters={"convergence": "linear, error halves each step", "requires": "f(a)*f(b) < 0"},
    ),

    "secant_method": FormulaInfo(
        algorithm="Secant Method",
        latex=r"x_{n+1} = x_n - f(x_n)\frac{x_n - x_{n-1}}{f(x_n) - f(x_{n-1})}",
        ascii="x_{n+1} = x_n - f(x_n)*(x_n - x_{n-1})/(f(x_n) - f(x_{n-1}))",
        method="Secant method: derivative-free root-finding. Superlinear convergence (order ~1.618).",
        reference="Burden & Faires, 'Numerical Analysis', 10th ed., Ch.2",
        parameters={"convergence": "superlinear, order phi=1.618", "no_derivative": "uses finite difference approx"},
    ),

    "thomas_algorithm": FormulaInfo(
        algorithm="Thomas Algorithm (Tridiagonal Solver)",
        latex=r"\begin{aligned} c'_i &= c_i / (b_i - a_i c'_{i-1}) \\ d'_i &= (d_i - a_i d'_{i-1}) / (b_i - a_i c'_{i-1}) \\ x_i &= d'_i - c'_i x_{i+1} \end{aligned}",
        ascii="Forward: c'_i = c_i/(b_i - a_i*c'_{i-1}); d'_i = (d_i - a_i*d'_{i-1})/(b_i - a_i*c'_{i-1}); Back: x_i = d'_i - c'_i*x_{i+1}",
        method="Thomas algorithm for tridiagonal systems. O(n) direct solver. Special case of LU for tridiagonal A.",
        reference="Thomas (1949); Conte & de Boor, 'Elementary Numerical Analysis'",
        parameters={"complexity": "O(n)", "requirement": "tridiagonal matrix", "stability": "diagonally dominant"},
    ),

    "simpson_rule": FormulaInfo(
        algorithm="Simpson's Rule",
        latex=r"\int_a^b f(x)\,dx \approx \frac{h}{3}\left[f(a) + 4f\!\left(\frac{a+b}{2}\right) + f(b)\right], \quad h = \frac{b-a}{2}",
        ascii="int_a^b f(x)dx ~ h/3 * [f(a) + 4*f((a+b)/2) + f(b)]; h=(b-a)/2",
        method="Simpson's 1/3 rule. Exact for polynomials up to degree 3. Error O(h^5).",
        reference="Burden & Faires, 'Numerical Analysis', 10th ed., Ch.4",
        parameters={"order": "4th order accurate", "error": "O(h^5*f''''(xi))"},
    ),

    "gauss_seidel": FormulaInfo(
        algorithm="Gauss-Seidel Iteration",
        latex=r"x_i^{(k+1)} = \frac{1}{a_{ii}}\left(b_i - \sum_{j<i} a_{ij} x_j^{(k+1)} - \sum_{j>i} a_{ij} x_j^{(k)}\right)",
        ascii="x_i^{k+1} = (b_i - sum(a_ij*x_j^{k+1}, j<i) - sum(a_ij*x_j^k, j>i)) / a_ii",
        method="Gauss-Seidel iterative method. Uses latest values immediately. Converges for diagonally dominant or SPD A.",
        reference="Saad, 'Iterative Methods for Sparse Linear Systems', Ch.4",
        parameters={"convergence": "spectral radius of iteration matrix < 1", "SOR": "over-relaxation variant with omega"},
    ),

    "jacobi_iteration": FormulaInfo(
        algorithm="Jacobi Iteration",
        latex=r"x_i^{(k+1)} = \frac{1}{a_{ii}}\left(b_i - \sum_{j \neq i} a_{ij} x_j^{(k)}\right)",
        ascii="x_i^{k+1} = (b_i - sum(a_ij*x_j^k, j!=i)) / a_ii",
        method="Jacobi iterative method. All updates use values from previous iteration. Easily parallelizable.",
        reference="Saad, 'Iterative Methods for Sparse Linear Systems', Ch.4",
        parameters={
            "convergence": "spectral radius of D^{-1}(L+U) < 1",
            "parallel": "fully parallelizable (no data dependency within iteration)",
        },
    ),

    "lanczos_algorithm": FormulaInfo(
        algorithm="Lanczos Algorithm",
        latex=r"AV_m = V_m T_m + \beta_{m+1} v_{m+1} e_m^T, \quad T_m = \text{tridiagonal}",
        ascii="A*V_m = V_m*T_m + beta_{m+1}*v_{m+1}*e_m^T; T_m is tridiagonal, eigenvalues of T_m approximate eigenvalues of A",
        method="Lanczos iteration for symmetric eigenvalue problems. Builds tridiagonal T_m from Krylov subspace.",
        reference="Lanczos (1950); Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.10",
        parameters={
            "requirement": "A must be symmetric",
            "T_m": "symmetric tridiagonal matrix",
            "reorthogonalization": "needed in practice for numerical stability",
        },
    ),

    "arnoldi_iteration": FormulaInfo(
        algorithm="Arnoldi Iteration",
        latex=r"AV_m = V_{m+1} \bar{H}_m, \quad \bar{H}_m \in \mathbb{R}^{(m+1)\times m} \text{ upper Hessenberg}",
        ascii="A*V_m = V_{m+1}*H_bar_m; H_bar is (m+1)xm upper Hessenberg; basis for GMRES",
        method="Arnoldi process for non-symmetric matrices. Builds orthonormal Krylov basis. Foundation of GMRES.",
        reference="Arnoldi (1951); Saad, 'Iterative Methods for Sparse Linear Systems', Ch.6",
        parameters={
            "H_m": "upper Hessenberg matrix",
            "V_m": "orthonormal basis of Krylov subspace",
            "cost": "O(m*n) per iteration + O(m^2) orthogonalization",
        },
    ),

    # ==================================================================
    # ADDITIONAL ML / DEEP LEARNING
    # ==================================================================

    "dropout_regularization": FormulaInfo(
        algorithm="Dropout Regularization",
        latex=r"\tilde{h} = m \odot h, \quad m_i \sim \text{Bernoulli}(p), \quad \hat{h}_\text{test} = p \cdot h",
        ascii="h_tilde = mask * h; mask ~ Bernoulli(p); at test time: h_test = p * h (or inverted: h_train = h/p)",
        method="Dropout: randomly zeroes activations during training. Prevents co-adaptation. Approximate ensemble.",
        reference="Srivastava et al. (2014), 'Dropout: A Simple Way to Prevent Neural Networks from Overfitting'",
        parameters={"p": "keep probability (0.5 for hidden, 0.8 for input)", "inverted": "scale by 1/p at train time"},
    ),

    "residual_connection": FormulaInfo(
        algorithm="Residual Connection (Skip Connection)",
        latex=r"y = \mathcal{F}(x, W) + x, \quad \text{or } y = \mathcal{F}(x, W) + W_s x",
        ascii="y = F(x, W) + x (identity shortcut); y = F(x, W) + W_s*x (projection shortcut)",
        method="Residual/skip connection. Enables training of very deep networks by learning residual mapping.",
        reference="He et al. (2016), 'Deep Residual Learning for Image Recognition'",
        parameters={"depth": "enables 100+ layer networks", "gradient_flow": "alleviates vanishing gradient"},
    ),

    "weight_decay_l2": FormulaInfo(
        algorithm="Weight Decay / L2 Regularization",
        latex=r"\mathcal{L}_\text{reg} = \mathcal{L} + \frac{\lambda}{2}\|\theta\|^2, \quad \theta_{t+1} = (1-\eta\lambda)\theta_t - \eta\nabla\mathcal{L}",
        ascii="L_reg = L + lambda/2 * ||theta||^2; theta_{t+1} = (1-lr*lambda)*theta_t - lr*grad(L)",
        method="L2 regularization / weight decay. Penalizes large weights to reduce overfitting.",
        reference="Goodfellow et al., 'Deep Learning' (2016), Ch.7; Loshchilov & Hutter (2019) for decoupled weight decay",
        parameters={"lambda": "regularization strength (1e-4 to 1e-2)", "decoupled": "AdamW separates weight decay from gradient"},
    ),

    "learning_rate_cosine_decay": FormulaInfo(
        algorithm="Cosine Annealing Learning Rate",
        latex=r"\eta_t = \eta_\text{min} + \frac{1}{2}(\eta_\text{max} - \eta_\text{min})\left(1 + \cos\!\left(\frac{t}{T}\pi\right)\right)",
        ascii="lr_t = lr_min + 0.5*(lr_max - lr_min)*(1 + cos(t/T * pi))",
        method="Cosine annealing schedule. Smooth decay from max to min learning rate over T steps.",
        reference="Loshchilov & Hutter (2017), 'SGDR: Stochastic Gradient Descent with Warm Restarts'",
        parameters={
            "T": "total number of steps/epochs",
            "lr_max": "initial learning rate",
            "lr_min": "minimum learning rate (often 0)",
            "warm_restart": "optional periodic restart (SGDR)",
        },
    ),

    "transformer_positional_encoding": FormulaInfo(
        algorithm="Positional Encoding (Sinusoidal)",
        latex=r"\begin{aligned} PE_{(pos,2i)} &= \sin(pos / 10000^{2i/d_\text{model}}) \\ PE_{(pos,2i+1)} &= \cos(pos / 10000^{2i/d_\text{model}}) \end{aligned}",
        ascii="PE(pos,2i) = sin(pos/10000^(2i/d_model)); PE(pos,2i+1) = cos(pos/10000^(2i/d_model))",
        method="Sinusoidal positional encoding for Transformers. Encodes position via sine/cosine at different frequencies.",
        reference="Vaswani et al. (2017), 'Attention Is All You Need'",
        parameters={"d_model": "model dimension", "pos": "sequence position", "i": "dimension index"},
    ),

    # ==================================================================
    # ADDITIONAL LINEAR ALGEBRA
    # ==================================================================

    "gram_schmidt": FormulaInfo(
        algorithm="Gram-Schmidt Orthogonalization",
        latex=r"q_k = v_k - \sum_{j=1}^{k-1} (v_k^T q_j) q_j, \quad q_k \leftarrow q_k / \|q_k\|",
        ascii="q_k = v_k - sum((v_k^T*q_j)*q_j, j=1..k-1); q_k = q_k/||q_k||",
        method="Classical Gram-Schmidt orthogonalization. Produces orthonormal basis. Use modified GS for stability.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.5",
        parameters={"classical": "numerically unstable", "modified": "recompute projections with updated q's"},
    ),

    "qr_factorization": FormulaInfo(
        algorithm="QR Factorization",
        latex=r"A = QR, \quad Q \in \mathbb{R}^{m \times n} \text{ orthogonal}, \quad R \in \mathbb{R}^{n \times n} \text{ upper triangular}",
        ascii="A = Q*R; Q orthogonal (Q^T*Q = I), R upper triangular",
        method="QR factorization via Householder reflections, Givens rotations, or Gram-Schmidt.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.5",
        parameters={
            "Householder": "O(2mn^2 - 2n^3/3) flops, most stable",
            "Givens": "good for sparse/banded, O(n) per zero",
            "Gram-Schmidt": "modified version for stability",
        },
    ),

    "condition_number": FormulaInfo(
        algorithm="Condition Number",
        latex=r"\kappa(A) = \|A\| \cdot \|A^{-1}\| = \frac{\sigma_\text{max}}{\sigma_\text{min}}",
        ascii="kappa(A) = ||A|| * ||A^{-1}|| = sigma_max / sigma_min",
        method="Matrix condition number. Measures sensitivity of Ax=b to perturbations. kappa>>1 means ill-conditioned.",
        reference="Golub & Van Loan, 'Matrix Computations', 4th ed., Ch.2",
        parameters={
            "well_conditioned": "kappa ~ 1",
            "ill_conditioned": "kappa >> 1",
            "error_bound": "||dx||/||x|| <= kappa * ||db||/||b||",
        },
    ),

    # ==================================================================
    # ADDITIONAL DSP
    # ==================================================================

    "kaiser_window": FormulaInfo(
        algorithm="Kaiser Window",
        latex=r"w[n] = \frac{I_0\!\left(\beta\sqrt{1-(2n/(N-1)-1)^2}\right)}{I_0(\beta)}",
        ascii="w[n] = I0(beta*sqrt(1-(2n/(N-1)-1)^2)) / I0(beta)",
        method="Kaiser window. Adjustable beta parameter controls mainlobe width vs sidelobe level trade-off.",
        reference="Kaiser (1974); Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.7",
        parameters={
            "beta": "shape parameter (higher = wider mainlobe, lower sidelobes)",
            "I0": "zeroth-order modified Bessel function of first kind",
        },
    ),

    "goertzel_algorithm": FormulaInfo(
        algorithm="Goertzel Algorithm",
        latex=r"s[n] = x[n] + 2\cos(2\pi k/N)\,s[n-1] - s[n-2], \quad X[k] = s[N-1] - e^{-i2\pi k/N}\,s[N-2]",
        ascii="s[n] = x[n] + 2*cos(2*pi*k/N)*s[n-1] - s[n-2]; X[k] = s[N-1] - exp(-i*2*pi*k/N)*s[N-2]",
        method="Goertzel algorithm: efficient single-frequency DFT bin computation. O(N) vs O(N log N) for full FFT.",
        reference="Goertzel (1958); Oppenheim & Schafer, 'Discrete-Time Signal Processing'",
        parameters={"complexity": "O(N) for single bin", "use": "DTMF detection, power spectrum at specific frequency"},
    ),

    "z_transform": FormulaInfo(
        algorithm="Z-Transform",
        latex=r"X(z) = \sum_{n=-\infty}^{\infty} x[n]\,z^{-n}, \quad H(z) = \frac{Y(z)}{X(z)} = \frac{\sum b_k z^{-k}}{\sum a_k z^{-k}}",
        ascii="X(z) = sum(x[n]*z^(-n)); H(z) = Y(z)/X(z) = sum(b_k*z^(-k))/sum(a_k*z^(-k))",
        method="Z-transform: discrete-time analog of Laplace transform. Transfer function H(z) characterizes LTI system.",
        reference="Oppenheim & Schafer, 'Discrete-Time Signal Processing', Ch.3",
        parameters={
            "ROC": "region of convergence",
            "poles": "z values where H(z)->inf (determine stability)",
            "zeros": "z values where H(z)=0",
        },
    ),

    # --- Quantitative Finance (v1.2.2) ---

    "black_scholes_merton": FormulaInfo(
        algorithm="black_scholes_merton",
        latex=r"C = S_0 N(d_1) - K e^{-rT} N(d_2), \quad d_1 = \frac{\ln(S/K) + (r + \sigma^2/2)T}{\sigma\sqrt{T}}, \quad d_2 = d_1 - \sigma\sqrt{T}",
        ascii="C = S_0 N(d_1) - K e^-rT N(d_2), d_1 = ((S/K) + (r + sigma^2/2)T)/(sigmasqrt(T)), d_2 = d_1 - sigmasqrt(T)",
        method="Black-Scholes-Merton European option pricing formula. The constants are from Abramowitz-Stegun rational approximation of the normal CDF.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hull_white_1f": FormulaInfo(
        algorithm="hull_white_1f",
        latex=r"dr_t = [\theta(t) - a \cdot r_t] dt + \sigma dW_t",
        ascii="dr_t = [theta(t) - a * r_t] dt + sigma dW_t",
        method="Hull-White one-factor short rate model. theta(t) calibrated to fit initial yield curve exactly.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hull_white_2f": FormulaInfo(
        algorithm="hull_white_2f",
        latex=r"r_t = x_t + y_t + \phi(t), \quad dx_t = -a x_t dt + \sigma_1 dW_t^1, \quad dy_t = -b y_t dt + \sigma_2 dW_t^2",
        ascii="r_t = x_t + y_t + phi(t), dx_t = -a x_t dt + sigma_1 dW_t^1, dy_t = -b y_t dt + sigma_2 dW_t^2",
        method="Hull-White two-factor (G2++) model. Two correlated mean-reverting factors plus a deterministic shift.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cox_ingersoll_ross": FormulaInfo(
        algorithm="cox_ingersoll_ross",
        latex=r"dr_t = \kappa(\theta - r_t)dt + \sigma\sqrt{r_t}dW_t",
        ascii="dr_t = kappa(theta - r_t)dt + sigmasqrt(r_t)dW_t",
        method="Cox-Ingersoll-Ross model. Square-root diffusion ensures non-negative rates when Feller condition 2*kappa*theta >= sigma^2 holds.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sabr_model": FormulaInfo(
        algorithm="sabr_model",
        latex=r"dF_t = \sigma_t F_t^\beta dW_t^1, \quad d\sigma_t = \alpha \sigma_t dW_t^2, \quad \text{corr}(dW^1, dW^2) = \rho",
        ascii="dF_t = sigma_t F_t^beta dW_t^1, dsigma_t = alpha sigma_t dW_t^2, corr(dW^1, dW^2) = rho",
        method="SABR stochastic alpha-beta-rho model. Hagan's asymptotic implied volatility formula widely used for swaption/cap smile.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "black_karasinski": FormulaInfo(
        algorithm="black_karasinski",
        latex=r"d\ln r_t = [\theta(t) - a \ln r_t]dt + \sigma dW_t",
        ascii="d r_t = [theta(t) - a r_t]dt + sigma dW_t",
        method="Black-Karasinski log-normal short rate model. Guarantees positive rates. No closed-form bond price, requires tree or PDE.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "local_volatility_dupire": FormulaInfo(
        algorithm="local_volatility_dupire",
        latex=r"\sigma_{\text{loc}}^2(K,T) = \frac{\frac{\partial C}{\partial T} + rK\frac{\partial C}{\partial K} + qC - qK\frac{\partial C}{\partial K}}{\frac{1}{2}K^2 \frac{\partial^2 C}{\partial K^2}}",
        ascii="sigma_loc^2(K,T) = (partial C)/(partial T) + rK(partial C)/(partial K) + qC - qK(partial C)/(partial K)(1)/(2)K^2 (parti",
        method="Dupire's local volatility formula. Derives local vol from market call prices or implied vol surface.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cev_model": FormulaInfo(
        algorithm="cev_model",
        latex=r"dS_t = \mu S_t dt + \sigma S_t^\beta dW_t",
        ascii="dS_t = mu S_t dt + sigma S_t^beta dW_t",
        method="Constant Elasticity of Variance model. beta<1 gives leverage effect (skew). Pricing uses non-central chi-squared distribution.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "merton_jump_diffusion": FormulaInfo(
        algorithm="merton_jump_diffusion",
        latex=r"dS_t = (\mu - \lambda k)S_t dt + \sigma S_t dW_t + S_t dJ_t, \quad J_t = \sum_{i=1}^{N_t}(Y_i - 1), \quad \ln Y \sim N(\mu_J, \sigma_J^2)",
        ascii="dS_t = (mu - lambda k)S_t dt + sigma S_t dW_t + S_t dJ_t, J_t = sum_i=1^N_t(Y_i - 1), Y N(mu_J, sigma_J^2)",
        method="Merton jump-diffusion model. GBM + compound Poisson jumps with log-normal jump sizes. Pricing via series expansion.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kou_double_exponential": FormulaInfo(
        algorithm="kou_double_exponential",
        latex=r"dS_t = (\mu - \lambda\zeta)S_t dt + \sigma S_t dW_t + S_t d\left(\sum_{i=1}^{N_t}(V_i - 1)\right), \quad f_Y(y) = p\eta_1 e^{-\eta_1 y}\mathbf{1}_{y\geq 0} + q\eta_2 e^{\eta_2 y}\mathbf{1}_{y<0}",
        ascii="dS_t = (mu - lambdazeta)S_t dt + sigma S_t dW_t + S_t d (sum_i=1^N_t(V_i - 1) ), f_Y(y) = peta_1 e^-eta_1 y1_y 0 + qeta_",
        method="Kou double-exponential jump-diffusion. Asymmetric jumps with different decay rates for up/down moves. Memoryless property enables analytical pricing.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bates_model": FormulaInfo(
        algorithm="bates_model",
        latex=r"dS_t = (\mu - \lambda k)S_t dt + \sqrt{v_t}S_t dW_t^S + S_t dJ_t, \quad dv_t = \kappa(\theta - v_t)dt + \xi\sqrt{v_t}dW_t^v",
        ascii="dS_t = (mu - lambda k)S_t dt + sqrt(v_t)S_t dW_t^S + S_t dJ_t, dv_t = kappa(theta - v_t)dt + xisqrt(v_t)dW_t^v",
        method="Bates model = Heston stochastic volatility + Merton-style log-normal jumps. Captures both volatility smile and short-term skew.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "binomial_tree_crr": FormulaInfo(
        algorithm="binomial_tree_crr",
        latex=r"u = e^{\sigma\sqrt{\Delta t}}, \quad d = e^{-\sigma\sqrt{\Delta t}} = 1/u, \quad p = \frac{e^{r\Delta t} - d}{u - d}",
        ascii="u = e^sigmasqrt( t), d = e^-sigmasqrt( t) = 1/u, p = e^r t - du - d",
        method="Cox-Ross-Rubinstein binomial tree. Recombining lattice for option pricing. Backward induction from terminal payoff.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "trinomial_tree": FormulaInfo(
        algorithm="trinomial_tree",
        latex=r"u = e^{\sigma\sqrt{2\Delta t}}, \quad d = 1/u, \quad m = 1, \quad p_u = \left(\frac{e^{r\Delta t/2} - e^{-\sigma\sqrt{\Delta t/2}}}{e^{\sigma\sqrt{\Delta t/2}} - e^{-\sigma\sqrt{\Delta t/2}}}\right)^2",
        ascii="u = e^sigmasqrt(2 t), d = 1/u, m = 1, p_u = (e^r t/2 - e^-sigmasqrt( t/2)e^sigmasqrt( t/2) - e^-sigmasqrt( t/2) )^2",
        method="Trinomial lattice model. Three branches (up/mid/down) per node. Better convergence than binomial for exotic options.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "longstaff_schwartz_lsmc": FormulaInfo(
        algorithm="longstaff_schwartz_lsmc",
        latex=r"\hat{C}(\omega; t_k) = \sum_{j=0}^{M} a_j L_j(S_{t_k}(\omega)), \quad \text{(Laguerre polynomial regression)}",
        ascii="C(omega; t_k) = sum_j=0^M a_j L_j(S_t_k(omega)), (Laguerre polynomial regression)",
        method="Longstaff-Schwartz Least Squares Monte Carlo for American option pricing. Regression of continuation value on basis functions of underlying.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "barone_adesi_whaley": FormulaInfo(
        algorithm="barone_adesi_whaley",
        latex=r"C_{Am} = C_{Eu} + A_2 \left(\frac{S}{S^*}\right)^{q_2}, \quad q_2 = \frac{-(n-1) + \sqrt{(n-1)^2 + 4M/K_c}}{2}",
        ascii="C_Am = C_Eu + A_2 ((S)/(S^*) )^q_2, q_2 = -(n-1) + sqrt((n-1)^2 + 4M/K_c)2",
        method="Barone-Adesi-Whaley quadratic approximation for American options. Fast closed-form approximation using critical stock price iteration.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "asian_option_geometric": FormulaInfo(
        algorithm="asian_option_geometric",
        latex=r"A_G = \left(\prod_{i=1}^{n} S_{t_i}\right)^{1/n}, \quad \sigma_G = \sigma\sqrt{\frac{(n+1)(2n+1)}{6n^2}}, \quad \mu_G = \left(r - \frac{\sigma^2}{2}\right)\frac{n+1}{2n} + \frac{\sigma_G^2}{2}",
        ascii="A_G = (prod_i=1^n S_t_i )^1/n, sigma_G = sigmasqrt(((n+1)(2n+1))/(6n^2)), mu_G = (r - (sigma^2)/(2) )(n+1)/(2n) + (sigma",
        method="Geometric Asian option. Product average has log-normal distribution -> closed-form BSM-style pricing. Used as control variate for arithmetic Asian.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "asian_option_arithmetic": FormulaInfo(
        algorithm="asian_option_arithmetic",
        latex=r"A = \frac{1}{n}\sum_{i=1}^{n} S_{t_i}, \quad \text{priced via MC or moment matching}",
        ascii="A = (1)/(n)sum_i=1^n S_t_i, priced via MC or moment matching",
        method="Arithmetic Asian option. No closed-form; priced via MC (often with geometric Asian as control variate) or moment-matching approximations.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "barrier_option": FormulaInfo(
        algorithm="barrier_option",
        latex=r"C_{di} = S e^{-qT}(H/S)^{2\lambda}N(y) - Ke^{-rT}(H/S)^{2\lambda-2}N(y - \sigma\sqrt{T}), \quad \lambda = \frac{r - q + \sigma^2/2}{\sigma^2}",
        ascii="C_di = S e^-qT(H/S)^2lambdaN(y) - Ke^-rT(H/S)^2lambda-2N(y - sigmasqrt(T)), lambda = (r - q + sigma^2/2)/(sigma^2)",
        method="Barrier options (knock-in/out, up/down). Closed-form for continuous barriers. Discrete monitoring requires correction (Broadie-Glasserman-Kou).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bermudan_swaption": FormulaInfo(
        algorithm="bermudan_swaption",
        latex=r"V_k = \max\left(\text{ExerciseValue}_k, \; E^Q[D(t_k, t_{k+1}) V_{k+1} | \mathcal{F}_{t_k}]\right)",
        ascii="V_k = (ExerciseValue_k, E^Q[D(t_k, t_k+1) V_k+1 | F_t_k] )",
        method="Bermudan swaption - exercisable on coupon dates. Priced via LSMC, tree methods, or PDE on short-rate models.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "lookback_option": FormulaInfo(
        algorithm="lookback_option",
        latex=r"C_{\text{float}} = S_T - S_{\min}, \quad C_{\text{fixed}} = \max(S_{\max} - K, 0)",
        ascii="C_float = S_T - S_, C_fixed = (S_ - K, 0)",
        method="Lookback options. Fixed or floating strike based on running max/min. Goldman-Sosin-Gatto closed-form for continuous monitoring.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cliquet_option": FormulaInfo(
        algorithm="cliquet_option",
        latex=r"\text{Payoff} = \sum_{i=1}^{N} \min\left(\text{cap}, \max\left(\text{floor}, \frac{S_{t_i} - S_{t_{i-1}}}{S_{t_{i-1}}}\right)\right)",
        ascii="Payoff = sum_i=1^N (cap, (floor, S_t_i - S_t_i-1S_t_i-1 ) )",
        method="Cliquet (ratchet) option. Sum of capped/floored periodic returns. Common in structured products. Requires stochastic vol model for accurate pricing.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rainbow_option": FormulaInfo(
        algorithm="rainbow_option",
        latex=r"\text{Payoff} = \max(\max(S_1, S_2, ..., S_n) - K, 0), \quad \text{(best-of call)}",
        ascii="Payoff = ((S_1, S_2, ..., S_n) - K, 0), (best-of call)",
        method="Rainbow options on multiple assets. Best-of, worst-of, spread. 2-asset case has Margrabe/Stulz closed-form. General case uses MC.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "quanto_option": FormulaInfo(
        algorithm="quanto_option",
        latex=r"C_Q = X_0 e^{-r_f T}[F e^{(r_d - r_f - \rho\sigma_S\sigma_X)T}N(d_1) - KN(d_2)]",
        ascii="C_Q = X_0 e^-r_f T[F e^(r_d - r_f - rhosigma_Ssigma_X)TN(d_1) - KN(d_2)]",
        method="Quanto option - payoff in foreign asset but settled in domestic currency at fixed FX rate. Requires FX-asset correlation adjustment.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "nelson_siegel": FormulaInfo(
        algorithm="nelson_siegel",
        latex=r"y(\tau) = \beta_0 + \beta_1 \frac{1 - e^{-\tau/\lambda}}{\tau/\lambda} + \beta_2 \left(\frac{1 - e^{-\tau/\lambda}}{\tau/\lambda} - e^{-\tau/\lambda}\right)",
        ascii="y(tau) = beta_0 + beta_1 1 - e^-tau/lambdatau/lambda + beta_2 (1 - e^-tau/lambdatau/lambda - e^-tau/lambda )",
        method="Nelson-Siegel yield curve model. Three factors: level (beta0), slope (beta1), curvature (beta2). Parsimonious and widely used by central banks.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "svensson_model": FormulaInfo(
        algorithm="svensson_model",
        latex=r"y(\tau) = \beta_0 + \beta_1 \frac{1 - e^{-\tau/\lambda_1}}{\tau/\lambda_1} + \beta_2 \left(\frac{1 - e^{-\tau/\lambda_1}}{\tau/\lambda_1} - e^{-\tau/\lambda_1}\right) + \beta_3 \left(\frac{1 - e^{-\tau/\lambda_2}}{\tau/\lambda_2} - e^{-\tau/\lambda_2}\right)",
        ascii="y(tau) = beta_0 + beta_1 1 - e^-tau/lambda_1tau/lambda_1 + beta_2 (1 - e^-tau/lambda_1tau/lambda_1 - e^-tau/lambda_1 ) +",
        method="Svensson (Nelson-Siegel-Svensson) extended model. Additional curvature term with second decay factor. Used by ECB, Bundesbank.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "yield_curve_bootstrap": FormulaInfo(
        algorithm="yield_curve_bootstrap",
        latex=r"P(0, T_n) = \frac{1 - c_n \sum_{i=1}^{n-1} \delta_i P(0, T_i)}{1 + c_n \delta_n}, \quad \text{(from par swap rates)}",
        ascii="P(0, T_n) = 1 - c_n sum_i=1^n-1 delta_i P(0, T_i)1 + c_n delta_n, (from par swap rates)",
        method="Yield curve bootstrapping. Sequential extraction of discount factors from deposits, futures, and swaps. Foundation of rates trading.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cubic_spline_interpolation": FormulaInfo(
        algorithm="cubic_spline_interpolation",
        latex=r"f(x) = a_i + b_i(x-x_i) + c_i(x-x_i)^2 + d_i(x-x_i)^3, \quad x \in [x_i, x_{i+1}]",
        ascii="f(x) = a_i + b_i(x-x_i) + c_i(x-x_i)^2 + d_i(x-x_i)^3, x [x_i, x_i+1]",
        method="Cubic spline interpolation for yield curves. Tridiagonal system solve. Natural or clamped boundary conditions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "monotone_convex": FormulaInfo(
        algorithm="monotone_convex",
        latex=r"f(t) = f_i + (f_{i+1} - f_i)g(x), \quad g(x) \text{ Hagan-West monotone convex}",
        ascii="f(t) = f_i + (f_i+1 - f_i)g(x), g(x) Hagan-West monotone convex",
        method="Monotone convex interpolation (Hagan-West). Guarantees positive forward rates and exact repricing of input instruments.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ois_discounting": FormulaInfo(
        algorithm="ois_discounting",
        latex=r"V_{\text{swap}} = \sum_{i} \delta_i (L_i + s) P^{OIS}(0, T_i) - \sum_j \delta_j c P^{OIS}(0, T_j)",
        ascii="V_swap = sum_i delta_i (L_i + s) P^OIS(0, T_i) - sum_j delta_j c P^OIS(0, T_j)",
        method="OIS discounting (post-2008 standard). Dual-curve framework: projection curve (LIBOR/SOFR) separate from discounting curve (OIS).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "var_historical": FormulaInfo(
        algorithm="var_historical",
        latex=r"\text{VaR}_{\alpha} = -F^{-1}_{PnL}(1-\alpha) = \text{Quantile}_{1-\alpha}(\text{losses})",
        ascii="VaR_alpha = -F^-1_PnL(1-alpha) = Quantile_1-alpha(losses)",
        method="Historical simulation VaR. Sort historical P&L, take quantile. No distributional assumption. 99% and 95% common confidence levels.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "var_parametric": FormulaInfo(
        algorithm="var_parametric",
        latex=r"\text{VaR}_{\alpha} = \mu_p + z_{\alpha} \sigma_p, \quad \sigma_p = \sqrt{w^T \Sigma w}",
        ascii="VaR_alpha = mu_p + z_alpha sigma_p, sigma_p = sqrt(w^T w)",
        method="Parametric (variance-covariance) VaR. Assumes normal returns. z=1.645 (95%), z=2.326 (99%). Portfolio variance via covariance matrix.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "var_monte_carlo": FormulaInfo(
        algorithm="var_monte_carlo",
        latex=r"\text{VaR}_{\alpha} = -\text{Quantile}_{1-\alpha}\left(\{\Delta V_i\}_{i=1}^N\right), \quad \Delta V_i = V(S_0 e^{(r-\sigma^2/2)\Delta t + \sigma\sqrt{\Delta t}Z_i}) - V(S_0)",
        ascii="VaR_alpha = -Quantile_1-alpha ( V_i_i=1^N ), V_i = V(S_0 e^(r-sigma^2/2) t + sigmasqrt( t)Z_i) - V(S_0)",
        method="Monte Carlo VaR. Full revaluation under simulated scenarios. Handles nonlinear exposures and fat tails.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "expected_shortfall_cvar": FormulaInfo(
        algorithm="expected_shortfall_cvar",
        latex=r"\text{ES}_{\alpha} = \frac{1}{1-\alpha}\int_{\alpha}^{1} \text{VaR}_u \, du = E[L | L > \text{VaR}_{\alpha}]",
        ascii="ES_alpha = (1)/(1-alpha)int_alpha^1 VaR_u du = E[L | L > VaR_alpha]",
        method="Expected Shortfall (CVaR). Average loss beyond VaR. Coherent risk measure (subadditive). Basel III requires ES at 97.5%.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cva_credit_valuation": FormulaInfo(
        algorithm="cva_credit_valuation",
        latex=r"\text{CVA} = (1-R) \int_0^T EE(t) \, dPD(t) \approx (1-R) \sum_{i=1}^{N} EE(t_i) \cdot [PD(t_i) - PD(t_{i-1})]",
        ascii="CVA = (1-R) int_0^T EE(t) dPD(t) (1-R) sum_i=1^N EE(t_i) * [PD(t_i) - PD(t_i-1)]",
        method="Credit Valuation Adjustment. Expected loss from counterparty default. Recovery rate typically 40%. EE = expected positive exposure.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dva_debit_valuation": FormulaInfo(
        algorithm="dva_debit_valuation",
        latex=r"\text{DVA} = (1-R_{\text{own}}) \int_0^T ENE(t) \, dPD_{\text{own}}(t)",
        ascii="DVA = (1-R_own) int_0^T ENE(t) dPD_own(t)",
        method="Debit Valuation Adjustment. Benefit from own default. Controversial. DVA = own-credit CVA from counterparty's perspective.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "fva_funding_valuation": FormulaInfo(
        algorithm="fva_funding_valuation",
        latex=r"\text{FVA} = -\int_0^T s_f(t) \cdot EE_{\text{uncoll}}(t) \cdot D(t) \, dt",
        ascii="FVA = -int_0^T s_f(t) * EE_uncoll(t) * D(t) dt",
        method="Funding Valuation Adjustment. Cost of funding uncollateralized exposure. Part of XVA framework.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_delta": FormulaInfo(
        algorithm="greeks_delta",
        latex=r"\Delta = \frac{\partial V}{\partial S} \approx \frac{V(S+h) - V(S-h)}{2h}, \quad \Delta_{\text{BSM}} = N(d_1)",
        ascii="= (partial V)/(partial S) (V(S+h) - V(S-h))/(2h), _BSM = N(d_1)",
        method="Delta - first derivative of option value w.r.t. underlying price. BSM call delta = N(d1). Central finite difference for numerical delta.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_gamma": FormulaInfo(
        algorithm="greeks_gamma",
        latex=r"\Gamma = \frac{\partial^2 V}{\partial S^2} \approx \frac{V(S+h) - 2V(S) + V(S-h)}{h^2}, \quad \Gamma_{\text{BSM}} = \frac{N'(d_1)}{S\sigma\sqrt{T}}",
        ascii="= (partial^2 V)/(partial S^2) (V(S+h) - 2V(S) + V(S-h))/(h^2), _BSM = (N'(d_1))/(Ssigmasqrt(T))",
        method="Gamma - second derivative of option value w.r.t. underlying. Measures delta sensitivity. Peaks at ATM near expiry.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_vega": FormulaInfo(
        algorithm="greeks_vega",
        latex=r"\mathcal{V} = \frac{\partial V}{\partial \sigma}, \quad \mathcal{V}_{\text{BSM}} = S\sqrt{T}N'(d_1)",
        ascii="V = (partial V)/(partial sigma), V_BSM = Ssqrt(T)N'(d_1)",
        method="Vega - sensitivity to implied volatility. Not a Greek letter (sometimes called kappa). Maximal for ATM options.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_theta": FormulaInfo(
        algorithm="greeks_theta",
        latex=r"\Theta = \frac{\partial V}{\partial t}, \quad \Theta_{\text{BSM}} = -\frac{SN'(d_1)\sigma}{2\sqrt{T}} - rKe^{-rT}N(d_2)",
        ascii="= (partial V)/(partial t), _BSM = -(SN'(d_1)sigma)/(2sqrt(T)) - rKe^-rTN(d_2)",
        method="Theta - time decay of option value. Usually negative for long options. Convention: per calendar day (/365) or per trading day (/252).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_rho": FormulaInfo(
        algorithm="greeks_rho",
        latex=r"\rho = \frac{\partial V}{\partial r}, \quad \rho_{\text{BSM}} = KTe^{-rT}N(d_2)",
        ascii="rho = (partial V)/(partial r), rho_BSM = KTe^-rTN(d_2)",
        method="Rho - sensitivity to risk-free interest rate. More significant for long-dated options.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_vanna": FormulaInfo(
        algorithm="greeks_vanna",
        latex=r"\text{Vanna} = \frac{\partial^2 V}{\partial S \partial \sigma} = \frac{\partial \Delta}{\partial \sigma} = \frac{\mathcal{V}}{S}\left(1 - \frac{d_1}{\sigma\sqrt{T}}\right)",
        ascii="Vanna = (partial^2 V)/(partial S partial sigma) = (partial )/(partial sigma) = VS (1 - (d_1)/(sigmasqrt(T)) )",
        method="Vanna - cross-Greek: d(delta)/d(vol) = d(vega)/d(spot). Important for volatility smile dynamics and risk management.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "greeks_volga": FormulaInfo(
        algorithm="greeks_volga",
        latex=r"\text{Volga} = \frac{\partial^2 V}{\partial \sigma^2} = \mathcal{V} \cdot \frac{d_1 d_2}{\sigma}",
        ascii="Volga = (partial^2 V)/(partial sigma^2) = V * (d_1 d_2)/(sigma)",
        method="Volga (Vomma) - second derivative w.r.t. volatility. Measures convexity of vega. Key for vanna-volga pricing method.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sobol_sequence": FormulaInfo(
        algorithm="sobol_sequence",
        latex=r"x_n^{(j)} = n_1 v_1^{(j)} \oplus n_2 v_2^{(j)} \oplus \cdots \oplus n_w v_w^{(j)}, \quad \text{(direction numbers)}",
        ascii="x_n^(j) = n_1 v_1^(j) n_2 v_2^(j) *s n_w v_w^(j), (direction numbers)",
        method="Sobol quasi-random sequence. Low-discrepancy for MC integration. Joe-Kuo direction numbers standard. Gray code generation for efficiency.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "halton_sequence": FormulaInfo(
        algorithm="halton_sequence",
        latex=r"H_b(n) = \sum_{i=0}^{\infty} d_i(n) b^{-(i+1)}, \quad n = \sum_{i=0}^{\infty} d_i(n) b^i",
        ascii="H_b(n) = sum_i=0^infty d_i(n) b^-(i+1), n = sum_i=0^infty d_i(n) b^i",
        method="Halton quasi-random sequence. Radical inverse function in different prime bases per dimension. Degrades in high dimensions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "brownian_bridge": FormulaInfo(
        algorithm="brownian_bridge",
        latex=r"W(t_m) = \frac{t_n - t_m}{t_n - t_k}W(t_k) + \frac{t_m - t_k}{t_n - t_k}W(t_n) + \sqrt{\frac{(t_m-t_k)(t_n-t_m)}{t_n-t_k}}\, Z",
        ascii="W(t_m) = (t_n - t_m)/(t_n - t_k)W(t_k) + (t_m - t_k)/(t_n - t_k)W(t_n) + sqrt(((t_m-t_k)(t_n-t_m))/(t_n-t_k)) Z",
        method="Brownian bridge path construction. Interpolates between known endpoints. Concentrates variance on important time steps. Pairs well with Sobol.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gauss_hermite_quadrature": FormulaInfo(
        algorithm="gauss_hermite_quadrature",
        latex=r"\int_{-\infty}^{\infty} f(x) e^{-x^2} dx \approx \sum_{i=1}^{n} w_i f(x_i)",
        ascii="int_-infty^infty f(x) e^-x^2 dx sum_i=1^n w_i f(x_i)",
        method="Gauss-Hermite quadrature for integrating f(x)*exp(-x^2). Used in finance for expectations over normal distribution. Nodes are roots of Hermite polynomials.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "brent_solver": FormulaInfo(
        algorithm="brent_solver",
        latex=r"\text{Brent's method: bisection + secant + inverse quadratic interpolation}",
        ascii="Brent's method: bisection + secant + inverse quadratic interpolation",
        method="Brent's root-finding method. Combines bisection, secant, and inverse quadratic interpolation. Guaranteed convergence. Used for implied vol solving.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "newton_raphson_implied_vol": FormulaInfo(
        algorithm="newton_raphson_implied_vol",
        latex=r"\sigma_{n+1} = \sigma_n - \frac{C_{BS}(\sigma_n) - C_{\text{market}}}{\text{Vega}(\sigma_n)}",
        ascii="sigma_n+1 = sigma_n - C_BS(sigma_n) - C_marketVega(sigma_n)",
        method="Newton-Raphson for implied volatility. Iterate sigma using vega as Jacobian. Initial guess ~0.2. Jaeckel's rational approximation as alternative.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "crank_nicolson_pde": FormulaInfo(
        algorithm="crank_nicolson_pde",
        latex=r"\frac{V_i^{n+1} - V_i^n}{\Delta t} = \frac{1}{2}\left[\mathcal{L}V^{n+1} + \mathcal{L}V^n\right], \quad \mathcal{L}V = \frac{1}{2}\sigma^2 S^2 \frac{\partial^2 V}{\partial S^2} + rS\frac{\partial V}{\partial S} - rV",
        ascii="V_i^n+1 - V_i^n t = (1)/(2) [LV^n+1 + LV^n ], LV = (1)/(2)sigma^2 S^2 (partial^2 V)/(partial S^2) + rS(partial V)/(parti",
        method="Crank-Nicolson finite difference scheme for Black-Scholes PDE. O(dt^2, dS^2). Tridiagonal system solved by Thomas algorithm. theta=0.5.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "adi_scheme": FormulaInfo(
        algorithm="adi_scheme",
        latex=r"V^{n+1/2} = V^n + \frac{\Delta t}{2}(A_1 V^{n+1/2} + A_2 V^n), \quad V^{n+1} = V^{n+1/2} + \frac{\Delta t}{2}(A_1 V^{n+1/2} + A_2 V^{n+1})",
        ascii="V^n+1/2 = V^n + ( t)/(2)(A_1 V^n+1/2 + A_2 V^n), V^n+1 = V^n+1/2 + ( t)/(2)(A_1 V^n+1/2 + A_2 V^n+1)",
        method="Alternating Direction Implicit for multi-factor PDEs (Heston, 2-factor rates). Douglas-Rachford, Craig-Sneyd, Hundsdorfer-Verwer variants.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "monte_carlo_gbm": FormulaInfo(
        algorithm="monte_carlo_gbm",
        latex=r"S_{t+\Delta t} = S_t \exp\left[(r - \frac{\sigma^2}{2})\Delta t + \sigma\sqrt{\Delta t}\, Z\right], \quad Z \sim N(0,1)",
        ascii="S_t+ t = S_t [(r - (sigma^2)/(2)) t + sigmasqrt( t) Z ], Z N(0,1)",
        method="Monte Carlo GBM path simulation. Exact log-normal simulation or Euler-Maruyama discretization. Antithetic variates for variance reduction.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "antithetic_variates": FormulaInfo(
        algorithm="antithetic_variates",
        latex=r"\hat{\mu} = \frac{1}{2N}\sum_{i=1}^{N}[f(Z_i) + f(-Z_i)]",
        ascii="mu = (1)/(2N)sum_i=1^N[f(Z_i) + f(-Z_i)]",
        method="Antithetic variates variance reduction. For each random Z, also evaluate at -Z. Halves variance for monotone payoffs at minimal cost.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "control_variates": FormulaInfo(
        algorithm="control_variates",
        latex=r"\hat{\mu}_{CV} = \hat{\mu}_f - \beta(\hat{\mu}_g - E[g]), \quad \beta = \frac{\text{Cov}(f,g)}{\text{Var}(g)}",
        ascii="mu_CV = mu_f - beta(mu_g - E[g]), beta = Cov(f,g)Var(g)",
        method="Control variates. Reduce MC variance using correlated random variable with known expectation. Geometric Asian as control for arithmetic Asian.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "importance_sampling": FormulaInfo(
        algorithm="importance_sampling",
        latex=r"E_P[f(X)] = E_Q\left[f(X)\frac{dP}{dQ}(X)\right], \quad \hat{\mu}_{IS} = \frac{1}{N}\sum_{i=1}^N f(X_i)\frac{p(X_i)}{q(X_i)}",
        ascii="E_P[f(X)] = E_Q [f(X)(dP)/(dQ)(X) ], mu_IS = (1)/(N)sum_i=1^N f(X_i)(p(X_i))/(q(X_i))",
        method="Importance sampling. Change probability measure to sample more from important regions. Girsanov theorem for drift change in diffusions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cholesky_decomposition": FormulaInfo(
        algorithm="cholesky_decomposition",
        latex=r"\Sigma = LL^T, \quad L_{ii} = \sqrt{\Sigma_{ii} - \sum_{k=1}^{i-1}L_{ik}^2}, \quad L_{ij} = \frac{\Sigma_{ij} - \sum_{k=1}^{j-1}L_{ik}L_{jk}}{L_{jj}}",
        ascii="= LL^T, L_ii = sqrt(_ii) - sum_k=1^i-1L_ik^2, L_ij = _ij - sum_k=1^j-1L_ikL_jkL_jj",
        method="Cholesky decomposition of correlation/covariance matrix. Generate correlated normal variates: Z_corr = L * Z_indep. O(n^3/3).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "jarrow_turnbull": FormulaInfo(
        algorithm="jarrow_turnbull",
        latex=r"\lambda(t) = -\frac{1}{1-R}\frac{d\ln S(t)}{dt}, \quad S(t) = e^{-\int_0^t \lambda(u) du}",
        ascii="lambda(t) = -(1)/(1-R)(d S(t))/(dt), S(t) = e^-int_0^t lambda(u) du",
        method="Jarrow-Turnbull reduced-form credit model. Default as Poisson event with hazard rate lambda. Calibrated from CDS spreads.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "merton_structural": FormulaInfo(
        algorithm="merton_structural",
        latex=r"E = V N(d_1) - D e^{-rT} N(d_2), \quad d_1 = \frac{\ln(V/D) + (r + \sigma_V^2/2)T}{\sigma_V \sqrt{T}}",
        ascii="E = V N(d_1) - D e^-rT N(d_2), d_1 = ((V/D) + (r + sigma_V^2/2)T)/(sigma_V sqrt(T))",
        method="Merton structural credit model. Equity as call on firm assets. Default when assets < liabilities at maturity. KMV distance-to-default.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cds_pricing": FormulaInfo(
        algorithm="cds_pricing",
        latex=r"s = \frac{(1-R)\sum_{i=1}^N DF(t_i)[S(t_{i-1}) - S(t_i)]}{\sum_{i=1}^N \Delta_i \cdot DF(t_i) \cdot S(t_i)}, \quad \text{(par spread)}",
        ascii="s = (1-R)sum_i=1^N DF(t_i)[S(t_i-1) - S(t_i)]sum_i=1^N _i * DF(t_i) * S(t_i), (par spread)",
        method="CDS par spread pricing. Protection leg (default payments) = Premium leg (spread payments). Recovery assumption typically 40%. Spread in bps.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "duration_macaulay": FormulaInfo(
        algorithm="duration_macaulay",
        latex=r"D_{\text{Mac}} = \frac{\sum_{i=1}^{N} t_i \frac{CF_i}{(1+y)^{t_i}}}{P}, \quad D_{\text{mod}} = \frac{D_{\text{Mac}}}{1+y/k}",
        ascii="D_Mac = sum_i=1^N t_i (CF_i)/((1+y)^t_i)P, D_mod = D_Mac1+y/k",
        method="Macaulay and modified duration. First-order price sensitivity to yield. DV01 = dollar value of 1bp = mod_duration * price * 0.0001.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "convexity": FormulaInfo(
        algorithm="convexity",
        latex=r"C = \frac{1}{P}\frac{\partial^2 P}{\partial y^2} = \frac{1}{P(1+y)^2}\sum_{i=1}^{N} \frac{t_i(t_i+1)CF_i}{(1+y)^{t_i}}",
        ascii="C = (1)/(P)(partial^2 P)/(partial y^2) = (1)/(P(1+y)^2)sum_i=1^N (t_i(t_i+1)CF_i)/((1+y)^t_i)",
        method="Bond convexity. Second-order yield sensitivity. Delta_P/P ~ -D*Delta_y + 0.5*C*(Delta_y)^2. Positive convexity benefits holder.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "implied_volatility_jaeckel": FormulaInfo(
        algorithm="implied_volatility_jaeckel",
        latex=r"\sigma_{\text{implied}} = \frac{1}{\sqrt{T}}\left[\text{RationalApprox}(\text{normalized price})\right]",
        ascii="sigma_implied = (1)/(sqrt(T)) [RationalApprox(normalized price) ]",
        method="Jaeckel's 'Let's Be Rational' implied vol. Machine-precision accuracy without iteration. Rational function approximation. Industry standard.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "svi_volatility_surface": FormulaInfo(
        algorithm="svi_volatility_surface",
        latex=r"w(k) = a + b\left(\rho(k-m) + \sqrt{(k-m)^2 + \sigma^2}\right), \quad k = \ln(K/F)",
        ascii="w(k) = a + b (rho(k-m) + sqrt((k-m)^2 + sigma^2) ), k = (K/F)",
        method="SVI (Stochastic Volatility Inspired) parameterization by Gatheral. 5 params: a (level), b (slope), rho (rotation), m (translation), sigma (curvature).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ssvi_surface": FormulaInfo(
        algorithm="ssvi_surface",
        latex=r"w(k, \theta_t) = \frac{\theta_t}{2}\left(1 + \rho\varphi(\theta_t)k + \sqrt{(\varphi(\theta_t)k + \rho)^2 + (1-\rho^2)}\right)",
        ascii="w(k, theta_t) = (theta_t)/(2) (1 + rho(theta_t)k + sqrt(((theta_t)k + rho)^2 + (1-rho^2)) )",
        method="SSVI (Surface SVI). Arbitrage-free extension of SVI across all maturities. phi(theta) typically power-law. Gatheral-Jacquier 2014.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "realized_vol_close_to_close": FormulaInfo(
        algorithm="realized_vol_close_to_close",
        latex=r"\hat{\sigma}_{CC}^2 = \frac{252}{n-1}\sum_{i=1}^{n}(r_i - \bar{r})^2, \quad r_i = \ln(C_i / C_{i-1})",
        ascii="sigma_CC^2 = (252)/(n-1)sum_i=1^n(r_i - r)^2, r_i = (C_i / C_i-1)",
        method="Close-to-close realized volatility. Annualized standard deviation of log returns. 252 trading days. Simplest estimator.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "parkinson_volatility": FormulaInfo(
        algorithm="parkinson_volatility",
        latex=r"\hat{\sigma}_P^2 = \frac{1}{4n\ln 2}\sum_{i=1}^{n}(\ln H_i - \ln L_i)^2",
        ascii="sigma_P^2 = (1)/(4n 2)sum_i=1^n( H_i - L_i)^2",
        method="Parkinson range-based volatility estimator. Uses high-low only. ~5x more efficient than close-to-close. Assumes no drift, continuous trading.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "garman_klass_volatility": FormulaInfo(
        algorithm="garman_klass_volatility",
        latex=r"\hat{\sigma}_{GK}^2 = \frac{1}{n}\sum_{i=1}^{n}\left[\frac{1}{2}(\ln H_i - \ln L_i)^2 - (2\ln 2 - 1)(\ln C_i - \ln O_i)^2\right]",
        ascii="sigma_GK^2 = (1)/(n)sum_i=1^n [(1)/(2)( H_i - L_i)^2 - (2 2 - 1)( C_i - O_i)^2 ]",
        method="Garman-Klass OHLC volatility estimator. Uses open, high, low, close. ~7.4x efficiency vs close-to-close. (2*ln2-1) = 0.386294.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "yang_zhang_volatility": FormulaInfo(
        algorithm="yang_zhang_volatility",
        latex=r"\hat{\sigma}_{YZ}^2 = \hat{\sigma}_o^2 + k\hat{\sigma}_c^2 + (1-k)\hat{\sigma}_{RS}^2, \quad k = \frac{0.34}{1.34 + \frac{n+1}{n-1}}",
        ascii="sigma_YZ^2 = sigma_o^2 + ksigma_c^2 + (1-k)sigma_RS^2, k = (0.34)/(1.34 + n+1)n-1",
        method="Yang-Zhang volatility. Combines overnight (open-close), Rogers-Satchell, and close-to-close components. Handles drift and opening jumps.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "garch_1_1": FormulaInfo(
        algorithm="garch_1_1",
        latex=r"\sigma_t^2 = \omega + \alpha \epsilon_{t-1}^2 + \beta \sigma_{t-1}^2, \quad \alpha + \beta < 1",
        ascii="sigma_t^2 = omega + alpha epsilon_t-1^2 + beta sigma_t-1^2, alpha + beta < 1",
        method="GARCH(1,1) conditional variance model. omega = long-run var weight, alpha = shock impact, beta = persistence. MLE estimation. alpha+beta = persistence.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ewma_volatility": FormulaInfo(
        algorithm="ewma_volatility",
        latex=r"\sigma_t^2 = \lambda \sigma_{t-1}^2 + (1-\lambda)r_{t-1}^2",
        ascii="sigma_t^2 = lambda sigma_t-1^2 + (1-lambda)r_t-1^2",
        method="EWMA (Exponentially Weighted Moving Average) volatility. Special case of GARCH with omega=0, alpha+beta=1. RiskMetrics lambda=0.94 (daily), 0.97 (monthly).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "vanna_volga_pricing": FormulaInfo(
        algorithm="vanna_volga_pricing",
        latex=r"V = V_{BS} + \frac{\text{Vanna}(K)}{\text{Vanna}(K_{25\Delta})}(V_{25\Delta} - V_{25\Delta}^{BS}) + \frac{\text{Volga}(K)}{\text{Volga}(K_{ATM})}(V_{ATM} - V_{ATM}^{BS})",
        ascii="V = V_BS + Vanna(K)Vanna(K_25)(V_25 - V_25^BS) + Volga(K)Volga(K_ATM)(V_ATM - V_ATM^BS)",
        method="Vanna-volga pricing method. FX market standard. Adjusts BS price using vanna/volga at market pillars (ATM, 25-delta). Model-free smile interpolation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "markowitz_mean_variance": FormulaInfo(
        algorithm="markowitz_mean_variance",
        latex=r"\min_w \frac{1}{2}w^T \Sigma w \quad \text{s.t.} \quad w^T \mu = \mu_p, \; w^T \mathbf{1} = 1",
        ascii="_w (1)/(2)w^T w s.t. w^T mu = mu_p, w^T 1 = 1",
        method="Markowitz mean-variance optimization. Quadratic programming for efficient frontier. Tangency portfolio maximizes Sharpe ratio.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "black_litterman": FormulaInfo(
        algorithm="black_litterman",
        latex=r"\mu_{BL} = [(\tau\Sigma)^{-1} + P^T \Omega^{-1} P]^{-1}[(\tau\Sigma)^{-1}\Pi + P^T \Omega^{-1} Q]",
        ascii="mu_BL = [(tau)^-1 + P^T ^-1 P]^-1[(tau)^-1 + P^T ^-1 Q]",
        method="Black-Litterman model. Combines equilibrium returns (CAPM implied) with investor views. tau typically 0.025-0.05. Omega = view uncertainty.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "risk_parity": FormulaInfo(
        algorithm="risk_parity",
        latex=r"w_i \frac{\partial \sigma_p}{\partial w_i} = w_j \frac{\partial \sigma_p}{\partial w_j} \quad \forall i,j, \quad RC_i = w_i \frac{(\Sigma w)_i}{\sqrt{w^T \Sigma w}}",
        ascii="w_i (partial sigma_p)/(partial w_i) = w_j (partial sigma_p)/(partial w_j) i,j, RC_i = w_i (( w)_i)/(sqrt(w^T w))",
        method="Risk parity / Equal Risk Contribution. Each asset contributes equally to portfolio risk. Bridgewater All-Weather style. Solved iteratively.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kelly_criterion": FormulaInfo(
        algorithm="kelly_criterion",
        latex=r"f^* = \frac{\mu - r}{\sigma^2}, \quad f^*_{\text{multi}} = \Sigma^{-1}(\mu - r\mathbf{1})",
        ascii="f^* = (mu - r)/(sigma^2), f^*_multi = ^-1(mu - r1)",
        method="Kelly criterion for optimal bet sizing. Maximizes log-wealth growth. Multi-asset: f = Sigma^{-1}*(mu-r). Half-Kelly common in practice.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "libor_market_model_bgm": FormulaInfo(
        algorithm="libor_market_model_bgm",
        latex=r"\frac{dL_i(t)}{L_i(t)} = \mu_i(t)dt + \sigma_i(t)\cdot dW(t), \quad \mu_i^Q = -\sum_{j=\eta(t)}^{i} \frac{\delta_j L_j(t)\sigma_j(t)\cdot\sigma_i(t)}{1+\delta_j L_j(t)}",
        ascii="(dL_i(t))/(L_i(t)) = mu_i(t)dt + sigma_i(t)* dW(t), mu_i^Q = -sum_j=eta(t)^i (delta_j L_j(t)sigma_j(t)*sigma_i(t))/(1+de",
        method="LIBOR Market Model (BGM). Models evolution of forward LIBOR rates. Drift correction for terminal measure. Calibrated to cap/swaption vols.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "swap_pricing": FormulaInfo(
        algorithm="swap_pricing",
        latex=r"V_{\text{swap}} = \sum_{i=1}^{N} \delta_i (L_i - K) P(0, T_i) \cdot N, \quad \text{par rate } K = \frac{P(0,T_0) - P(0,T_N)}{\sum_{i=1}^N \delta_i P(0,T_i)}",
        ascii="V_swap = sum_i=1^N delta_i (L_i - K) P(0, T_i) * N, par rate K = (P(0,T_0) - P(0,T_N))/(sum_i=1)^N delta_i P(0,T_i)",
        method="Interest rate swap pricing. Fixed vs floating leg NPV. Par swap rate equates PV of legs. Annuity factor = sum of discounted day fractions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "black76_swaption": FormulaInfo(
        algorithm="black76_swaption",
        latex=r"V = A \cdot [S \cdot N(d_1) - K \cdot N(d_2)] \cdot \omega, \quad d_1 = \frac{\ln(S/K) + \sigma^2 T/2}{\sigma\sqrt{T}}, \quad A = \sum \delta_i P(0,T_i)",
        ascii="V = A * [S * N(d_1) - K * N(d_2)] * omega, d_1 = ((S/K) + sigma^2 T/2)/(sigmasqrt(T)), A = sum delta_i P(0,T_i)",
        method="Black-76 model for swaptions and caps. Forward-measure pricing with annuity as numeraire. Vol is lognormal (Black) or normal (Bachelier).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bachelier_normal_model": FormulaInfo(
        algorithm="bachelier_normal_model",
        latex=r"C = (F-K)N(d) + \sigma_N\sqrt{T}\phi(d), \quad d = \frac{F-K}{\sigma_N\sqrt{T}}",
        ascii="C = (F-K)N(d) + sigma_Nsqrt(T)phi(d), d = (F-K)/(sigma_Nsqrt(T))",
        method="Bachelier (normal) model. Arithmetic Brownian motion. Used when rates can be negative. Normal vol in bp. Standard for rates post-2014.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "copula_gaussian": FormulaInfo(
        algorithm="copula_gaussian",
        latex=r"C(u_1,...,u_n) = \Phi_n(\Phi^{-1}(u_1),...,\Phi^{-1}(u_n); \Sigma), \quad \text{default correlation}",
        ascii="C(u_1,...,u_n) = _n(^-1(u_1),...,^-1(u_n); ), default correlation",
        method="Gaussian copula for credit portfolio modeling. Li (2000) CDO pricing. Base correlation from market. One-factor model for computational efficiency.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "t_copula": FormulaInfo(
        algorithm="t_copula",
        latex=r"C_\nu(u_1,...,u_n) = t_{\nu,\Sigma}(t_\nu^{-1}(u_1),...,t_\nu^{-1}(u_n))",
        ascii="C_nu(u_1,...,u_n) = t_nu,(t_nu^-1(u_1),...,t_nu^-1(u_n))",
        method="Student-t copula. Tail dependence unlike Gaussian copula. nu = degrees of freedom controls tail heaviness. Better for stress scenarios.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "twap": FormulaInfo(
        algorithm="twap",
        latex=r"q_i = \frac{Q}{N}, \quad i = 1,...,N \quad \text{(equal slices over N intervals)}",
        ascii="q_i = (Q)/(N), i = 1,...,N (equal slices over N intervals)",
        method="TWAP (Time Weighted Average Price). Execute equal quantities at regular intervals. Simplest execution algorithm. Benchmark for execution quality.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "vwap_algorithm": FormulaInfo(
        algorithm="vwap_algorithm",
        latex=r"q_i = Q \cdot \frac{\hat{v}_i}{\sum_j \hat{v}_j}, \quad \text{VWAP} = \frac{\sum p_i v_i}{\sum v_i}",
        ascii="q_i = Q * v_isum_j v_j, VWAP = (sum p_i v_i)/(sum v_i)",
        method="VWAP execution algorithm. Trade proportional to historical volume profile. Minimize deviation from volume-weighted average price.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "almgren_chriss": FormulaInfo(
        algorithm="almgren_chriss",
        latex=r"x_k = X\frac{\sinh(\kappa(T-t_k))}{\sinh(\kappa T)}, \quad \kappa = \sqrt{\frac{\lambda\sigma^2}{\eta}}, \quad \text{cost} = \gamma x^2 + \eta |\dot{x}|",
        ascii="x_k = X((kappa(T-t_k)))/((kappa T)), kappa = sqrt((lambdasigma^2)/(eta)), cost = gamma x^2 + eta |x|",
        method="Almgren-Chriss optimal execution. Balances execution risk vs market impact cost. kappa = urgency parameter. Exponential trajectory shape.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "carr_madan_fft": FormulaInfo(
        algorithm="carr_madan_fft",
        latex=r"C(K) = \frac{e^{-\alpha k}}{\pi}\int_0^\infty e^{-ivk}\frac{e^{-rT}\phi_T(v-(\alpha+1)i)}{\alpha^2+\alpha-v^2+i(2\alpha+1)v}dv",
        ascii="C(K) = e^-alpha kpiint_0^infty e^-ivke^-rTphi_T(v-(alpha+1)i)alpha^2+alpha-v^2+i(2alpha+1)vdv",
        method="Carr-Madan FFT option pricing. Price entire strike spectrum at once via FFT of characteristic function. Alpha = damping parameter ~1.5.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cos_method": FormulaInfo(
        algorithm="cos_method",
        latex=r"V = e^{-rT}\sum_{k=0}^{N-1} \text{Re}\left[\phi\left(\frac{k\pi}{b-a}\right)e^{-ik\pi\frac{a}{b-a}}\right]V_k",
        ascii="V = e^-rTsum_k=0^N-1 Re [phi ((kpi)/(b-a) )e^-ikpi(a)/(b-a) ]V_k",
        method="COS method (Fang-Oosterlee). Fourier-cosine series expansion for option pricing. Exponential convergence. Fast for European and Bermudan options.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "lewis_option_pricing": FormulaInfo(
        algorithm="lewis_option_pricing",
        latex=r"C = S - \frac{\sqrt{K}e^{-rT/2}}{\pi}\int_0^\infty \text{Re}\left[e^{iuk}\phi(u-i/2)\frac{1}{u^2+1/4}\right]du",
        ascii="C = S - sqrt(K)e^-rT/2piint_0^infty Re [e^iukphi(u-i/2)(1)/(u^2+1/4) ]du",
        method="Lewis (2001) option pricing via generalized Fourier transform. Alternative to Carr-Madan. No damping parameter needed.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "finite_difference_explicit": FormulaInfo(
        algorithm="finite_difference_explicit",
        latex=r"V_i^{n} = p_u V_{i+1}^{n+1} + p_m V_i^{n+1} + p_d V_{i-1}^{n+1}, \quad \text{stability: } \Delta t \leq \frac{(\Delta S)^2}{\sigma^2 S_{\max}^2}",
        ascii="V_i^n = p_u V_i+1^n+1 + p_m V_i^n+1 + p_d V_i-1^n+1, stability: t (( S)^2)/(sigma^2 S_)^2",
        method="Explicit finite difference for BSM PDE. Forward Euler in time. CFL stability condition on dt. Simple but requires small time steps.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "finite_difference_implicit": FormulaInfo(
        algorithm="finite_difference_implicit",
        latex=r"V_i^{n} = V_i^{n+1} - \Delta t \cdot \mathcal{L}V^n, \quad \text{(unconditionally stable)}",
        ascii="V_i^n = V_i^n+1 - t * LV^n, (unconditionally stable)",
        method="Fully implicit finite difference. Backward Euler in time. Unconditionally stable. First-order time accuracy. Tridiagonal system each step.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "psor_american_fd": FormulaInfo(
        algorithm="psor_american_fd",
        latex=r"V_i^{(k+1)} = \max\left(g_i, \; V_i^{(k)} + \omega\left(\frac{b_i - \sum_j a_{ij}V_j^{(k+1)}}{a_{ii}} - V_i^{(k)}\right)\right)",
        ascii="V_i^(k+1) = (g_i, V_i^(k) + omega (b_i - sum_j a_ijV_j^(k+1)a_ii - V_i^(k) ) )",
        method="Projected SOR for American options via FD. Linear complementarity problem. Over-relaxation parameter omega in (1,2). Alternative: penalty method.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "milstein_scheme": FormulaInfo(
        algorithm="milstein_scheme",
        latex=r"X_{n+1} = X_n + a(X_n)\Delta t + b(X_n)\Delta W_n + \frac{1}{2}b(X_n)b'(X_n)(\Delta W_n^2 - \Delta t)",
        ascii="X_n+1 = X_n + a(X_n) t + b(X_n) W_n + (1)/(2)b(X_n)b'(X_n)( W_n^2 - t)",
        method="Milstein SDE discretization. Strong order 1.0 (vs 0.5 for Euler). Requires derivative of diffusion coefficient. Better path accuracy.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "euler_maruyama": FormulaInfo(
        algorithm="euler_maruyama",
        latex=r"X_{n+1} = X_n + \mu(X_n, t_n)\Delta t + \sigma(X_n, t_n)\sqrt{\Delta t}\, Z_n",
        ascii="X_n+1 = X_n + mu(X_n, t_n) t + sigma(X_n, t_n)sqrt( t) Z_n",
        method="Euler-Maruyama SDE discretization. Simplest scheme: strong order 0.5, weak order 1.0. Foundation of MC simulation in finance.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "qe_scheme_heston": FormulaInfo(
        algorithm="qe_scheme_heston",
        latex=r"v_{t+\Delta t} = a(b+Z_v)^2 \text{ if } \psi \leq \psi_c, \quad \text{else } v = \Psi^{-1}(U; p, \beta)",
        ascii="v_t+ t = a(b+Z_v)^2 if psi psi_c, else v = ^-1(U; p, beta)",
        method="Andersen's QE (Quadratic-Exponential) scheme for Heston. Moment-matched discretization of variance process. Psi_c ~ 1.5. Industry standard for Heston MC.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "broadie_glasserman_kou": FormulaInfo(
        algorithm="broadie_glasserman_kou",
        latex=r"H_{\text{eff}} = H \cdot e^{\pm \beta \sigma \sqrt{\Delta t}}, \quad \beta \approx 0.5826",
        ascii="H_eff = H * e^ beta sigma sqrt( t), beta 0.5826",
        method="Broadie-Glasserman-Kou continuity correction for discrete barrier options. Shifts barrier by beta*sigma*sqrt(dt). beta = -zeta(1/2)/sqrt(2*pi) ~ 0.5826.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "heston_semi_analytical": FormulaInfo(
        algorithm="heston_semi_analytical",
        latex=r"C = S P_1 - K e^{-rT} P_2, \quad P_j = \frac{1}{2} + \frac{1}{\pi}\int_0^\infty \text{Re}\left[\frac{e^{-iu\ln K}f_j(u)}{iu}\right]du",
        ascii="C = S P_1 - K e^-rT P_2, P_j = (1)/(2) + (1)/(pi)int_0^infty Re [e^-iu Kf_j(u)iu ]du",
        method="Heston semi-analytical pricing via characteristic function integration. P1, P2 probabilities computed numerically (Gauss-Laguerre or adaptive). Two formulations (original vs Albrecher).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dv01": FormulaInfo(
        algorithm="dv01",
        latex=r"\text{DV01} = -\frac{\partial P}{\partial y} \cdot 0.0001 \approx \frac{P(y-0.5bp) - P(y+0.5bp)}{0.0001}",
        ascii="DV01 = -(partial P)/(partial y) * 0.0001 (P(y-0.5bp) - P(y+0.5bp))/(0.0001)",
        method="DV01 / PV01 - Dollar value of one basis point. Price change for 1bp parallel shift in yield curve. Key fixed income risk measure.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "key_rate_duration": FormulaInfo(
        algorithm="key_rate_duration",
        latex=r"\text{KRD}_k = -\frac{1}{P}\frac{P(y_k + \Delta y) - P(y_k - \Delta y)}{2\Delta y}",
        ascii="KRD_k = -(1)/(P)(P(y_k + y) - P(y_k - y))/(2 y)",
        method="Key rate duration. Sensitivity to individual tenor point shifts (not parallel). Decomposes DV01 across the curve. Risk bucketing.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "monte_carlo_heston": FormulaInfo(
        algorithm="monte_carlo_heston",
        latex=r"\ln S_{t+\Delta t} = \ln S_t + (r - v_t/2)\Delta t + \sqrt{v_t}(\rho Z_1 + \sqrt{1-\rho^2}Z_2)\sqrt{\Delta t}",
        ascii="S_t+ t = S_t + (r - v_t/2) t + sqrt(v_t)(rho Z_1 + sqrt(1-rho^2)Z_2)sqrt( t)",
        method="Monte Carlo for Heston model. Discretize both spot and variance. Full truncation or reflection for variance positivity. QE scheme preferred.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "box_muller": FormulaInfo(
        algorithm="box_muller",
        latex=r"Z_1 = \sqrt{-2\ln U_1}\cos(2\pi U_2), \quad Z_2 = \sqrt{-2\ln U_1}\sin(2\pi U_2)",
        ascii="Z_1 = sqrt(-2 U_1)(2pi U_2), Z_2 = sqrt(-2 U_1)(2pi U_2)",
        method="Box-Muller transform. Generate normal variates from uniform. Marsaglia polar method as faster alternative. Ziggurat for maximum speed.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mersenne_twister": FormulaInfo(
        algorithm="mersenne_twister",
        latex=r"x_{k+n} = x_{k+m} \oplus (x_k^u | x_{k+1}^l) A, \quad \text{period } 2^{19937}-1",
        ascii="x_k+n = x_k+m (x_k^u | x_k+1^l) A, period 2^19937-1",
        method="Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State array of 624 32-bit integers. Tempering for equidistribution.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "interest_rate_cap_floor": FormulaInfo(
        algorithm="interest_rate_cap_floor",
        latex=r"\text{Caplet} = \delta \cdot P(0,T_{i+1}) \cdot [F_i N(d_1) - K N(d_2)], \quad \text{Cap} = \sum \text{Caplets}",
        ascii="Caplet = delta * P(0,T_i+1) * [F_i N(d_1) - K N(d_2)], Cap = sum Caplets",
        method="Interest rate caps and floors. Sum of caplets/floorlets. Black-76 pricing per caplet. Flat vol vs spot vol. Cap-floor parity.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "digital_option": FormulaInfo(
        algorithm="digital_option",
        latex=r"C_{\text{digital}} = e^{-rT}N(d_2), \quad P_{\text{digital}} = e^{-rT}N(-d_2)",
        ascii="C_digital = e^-rTN(d_2), P_digital = e^-rTN(-d_2)",
        method="Digital (binary) option. Cash-or-nothing pays fixed amount if ITM. Asset-or-nothing pays asset value. Hedging requires spread replication.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "compound_option": FormulaInfo(
        algorithm="compound_option",
        latex=r"C_{\text{on}C} = SN_2(a_1, b_1; \rho) - K_2 e^{-rT_2}N_2(a_2, b_2; \rho) - K_1 e^{-rT_1}N(a_2)",
        ascii="C_onC = SN_2(a_1, b_1; rho) - K_2 e^-rT_2N_2(a_2, b_2; rho) - K_1 e^-rT_1N(a_2)",
        method="Compound option (option on option). Geske formula uses bivariate normal. Call-on-call, call-on-put, etc. Used in real options and split-fee structures.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "variance_swap": FormulaInfo(
        algorithm="variance_swap",
        latex=r"\text{Fair strike} = K_{var} = \frac{2e^{rT}}{T}\left[\int_0^{F} \frac{P(K)}{K^2}dK + \int_F^{\infty}\frac{C(K)}{K^2}dK\right]",
        ascii="Fair strike = K_var = 2e^rTT [int_0^F (P(K))/(K^2)dK + int_F^infty(C(K))/(K^2)dK ]",
        method="Variance swap fair value. Replicates with strip of OTM options weighted by 1/K^2. Basis of VIX calculation. Convexity adjustment for discrete monitoring.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "vix_calculation": FormulaInfo(
        algorithm="vix_calculation",
        latex=r"\text{VIX}^2 = \frac{2}{T}\sum_i \frac{\Delta K_i}{K_i^2}e^{rT}Q(K_i) - \frac{1}{T}\left(\frac{F}{K_0} - 1\right)^2",
        ascii="VIX^2 = (2)/(T)sum_i ( K_i)/(K_i^2)e^rTQ(K_i) - (1)/(T) ((F)/(K_0) - 1 )^2",
        method="CBOE VIX calculation. Model-free implied volatility from SPX options. 30-day target. OTM puts and calls weighted by 1/K^2. Interpolated between two expirations.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "holee_model": FormulaInfo(
        algorithm="holee_model",
        latex=r"dr_t = \theta(t) dt + \sigma dW_t",
        ascii="dr_t = theta(t) dt + sigma dW_t",
        method="Ho-Lee short rate model. Simplest no-arbitrage model. Normal dynamics, rates can go negative. theta(t) fits initial yield curve.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bdt_model": FormulaInfo(
        algorithm="bdt_model",
        latex=r"d\ln r_t = [\theta(t) + \frac{\sigma'(t)}{\sigma(t)}\ln r_t]dt + \sigma(t)dW_t",
        ascii="d r_t = [theta(t) + (sigma'(t))/(sigma(t)) r_t]dt + sigma(t)dW_t",
        method="Black-Derman-Toy lognormal short rate model. Time-dependent vol and mean reversion. Calibrated via binomial tree to cap vols and yield curve.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "lognormal_forward_libor": FormulaInfo(
        algorithm="lognormal_forward_libor",
        latex=r"\text{Caplet}_i = \delta_i P(0,T_{i+1})[F_i N(d_1) - K N(d_2)], \quad d_1 = \frac{\ln(F_i/K) + \sigma_i^2 T_i/2}{\sigma_i\sqrt{T_i}}",
        ascii="Caplet_i = delta_i P(0,T_i+1)[F_i N(d_1) - K N(d_2)], d_1 = ((F_i/K) + sigma_i^2 T_i/2)/(sigma_isqrt(T_i))",
        method="Lognormal forward LIBOR model for caplet pricing. Each forward rate follows GBM under its forward measure. Black formula per caplet.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "fx_garman_kohlhagen": FormulaInfo(
        algorithm="fx_garman_kohlhagen",
        latex=r"C = S e^{-r_f T}N(d_1) - K e^{-r_d T}N(d_2), \quad d_1 = \frac{\ln(S/K) + (r_d - r_f + \sigma^2/2)T}{\sigma\sqrt{T}}",
        ascii="C = S e^-r_f TN(d_1) - K e^-r_d TN(d_2), d_1 = ((S/K) + (r_d - r_f + sigma^2/2)T)/(sigmasqrt(T))",
        method="Garman-Kohlhagen FX option pricing. BSM adjusted for two interest rates (domestic/foreign). FX forward: F = S * exp((r_d - r_f)*T).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "quanto_adjustment": FormulaInfo(
        algorithm="quanto_adjustment",
        latex=r"\mu_{\text{quanto}} = \mu - \rho_{SX}\sigma_S\sigma_X, \quad \text{(drift adjustment for quanto)}",
        ascii="mu_quanto = mu - rho_SXsigma_Ssigma_X, (drift adjustment for quanto)",
        method="Quanto drift adjustment. Foreign asset drift reduced by rho*sigma_S*sigma_X under domestic measure. Appears in equity-FX hybrid models.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "credit_triangle": FormulaInfo(
        algorithm="credit_triangle",
        latex=r"s \approx \lambda \cdot (1-R), \quad \lambda = \frac{s}{1-R}",
        ascii="s lambda * (1-R), lambda = (s)/(1-R)",
        method="Credit triangle approximation. CDS spread ~ hazard rate * (1 - recovery). Quick estimation. Exact for flat curves and continuous premium.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "transition_matrix": FormulaInfo(
        algorithm="transition_matrix",
        latex=r"P(t+\Delta t) = P(t) \cdot \Lambda, \quad \Lambda_{ij} = P(\text{rating } i \to j), \quad G = \frac{1}{\Delta t}\ln \Lambda",
        ascii="P(t+ t) = P(t) * , _ij = P(rating i j), G = (1)/( t)",
        method="Credit rating transition matrix. Markov chain model of rating migrations. Generator matrix for continuous-time. Used in credit portfolio risk.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "delta_hedging": FormulaInfo(
        algorithm="delta_hedging",
        latex=r"\Pi = V - \Delta \cdot S, \quad d\Pi = (\Theta + \frac{1}{2}\Gamma \sigma^2 S^2)dt",
        ascii="= V - * S, d = ( + (1)/(2) sigma^2 S^2)dt",
        method="Delta hedging. Maintain delta-neutral portfolio. P&L from gamma and theta: Theta + 0.5*Gamma*sigma^2*S^2*dt = 0 for BSM. Discrete rebalancing creates hedge error.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "marginal_var": FormulaInfo(
        algorithm="marginal_var",
        latex=r"\text{MVaR}_i = \frac{\partial \text{VaR}_p}{\partial w_i} = \frac{(\Sigma w)_i}{\sigma_p} \cdot z_\alpha",
        ascii="MVaR_i = partial VaR_ppartial w_i = (( w)_i)/(sigma_p) * z_alpha",
        method="Marginal and component VaR. Marginal: VaR sensitivity to position change. Component: Euler allocation, sums to total VaR. Portfolio risk attribution.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "stress_testing_scenario": FormulaInfo(
        algorithm="stress_testing_scenario",
        latex=r"\Delta V = \sum_i \frac{\partial V}{\partial x_i}\Delta x_i + \frac{1}{2}\sum_{i,j}\frac{\partial^2 V}{\partial x_i \partial x_j}\Delta x_i \Delta x_j + ...",
        ascii="V = sum_i (partial V)/(partial x_i) x_i + (1)/(2)sum_i,j(partial^2 V)/(partial x_i partial x_j) x_i x_j + ...",
        method="Stress testing via Taylor expansion or full revaluation. Historical scenarios (2008, COVID) or hypothetical. Regulatory requirement (CCAR, DFAST).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "exponential_interpolation": FormulaInfo(
        algorithm="exponential_interpolation",
        latex=r"P(t) = P(t_i)\left(\frac{P(t_{i+1})}{P(t_i)}\right)^{\frac{t-t_i}{t_{i+1}-t_i}}, \quad \text{(log-linear discount factors)}",
        ascii="P(t) = P(t_i) (P(t_i+1)P(t_i) )^(t-t_i)/(t_i+1)-t_i, (log-linear discount factors)",
        method="Log-linear (exponential) interpolation of discount factors. Equivalent to piecewise constant forward rates. Simplest yield curve interpolation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "day_count_convention": FormulaInfo(
        algorithm="day_count_convention",
        latex=r"\delta_{30/360} = \frac{360(Y_2-Y_1)+30(M_2-M_1)+(D_2-D_1)}{360}, \quad \delta_{\text{ACT/365}} = \frac{\text{actual days}}{365}",
        ascii="delta_30/360 = (360(Y_2-Y_1)+30(M_2-M_1)+(D_2-D_1))/(360), delta_ACT/365 = actual days365",
        method="Day count conventions for accrual calculation. ACT/360 (money market), ACT/365 (UK), 30/360 (bonds), ACT/ACT (ISDA/ISMA). Critical for exact pricing.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "schedule_generation": FormulaInfo(
        algorithm="schedule_generation",
        latex=r"T_i = \text{Adjust}(T_0 + i \cdot \text{period}, \text{calendar}, \text{convention})",
        ascii="T_i = Adjust(T_0 + i * period, calendar, convention)",
        method="Payment schedule generation. Business day conventions: Following, Modified Following, Preceding. End-of-month rule. Stub periods (short/long front/back).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "normal_cdf_approximation": FormulaInfo(
        algorithm="normal_cdf_approximation",
        latex=r"N(x) = 1 - n(x)(b_1 t + b_2 t^2 + b_3 t^3 + b_4 t^4 + b_5 t^5), \quad t = \frac{1}{1 + 0.2316419 x}",
        ascii="N(x) = 1 - n(x)(b_1 t + b_2 t^2 + b_3 t^3 + b_4 t^4 + b_5 t^5), t = (1)/(1 + 0.2316419 x)",
        method="Normal CDF rational approximation (Abramowitz-Stegun). These specific constants are a strong fingerprint in decompiled code. Also look for erfc-based implementations.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "normal_inverse_cdf": FormulaInfo(
        algorithm="normal_inverse_cdf",
        latex=r"x = t - \frac{c_0 + c_1 t + c_2 t^2}{1 + d_1 t + d_2 t^2 + d_3 t^3}, \quad t = \sqrt{-2\ln(p)}",
        ascii="x = t - (c_0 + c_1 t + c_2 t^2)/(1 + d_1 t + d_2 t^2 + d_3 t^3), t = sqrt(-2(p))",
        method="Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational approximation. Constants are distinctive signatures.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "feller_condition_check": FormulaInfo(
        algorithm="feller_condition_check",
        latex=r"2\kappa\theta \geq \xi^2 \quad \text{(ensures } v_t > 0 \text{ a.s.)}",
        ascii="2kappatheta xi^2 (ensures v_t > 0 a.s.)",
        method="Feller condition check for CIR/Heston variance processes. If violated, variance can hit zero. Reflected or truncated schemes needed.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "girsanov_measure_change": FormulaInfo(
        algorithm="girsanov_measure_change",
        latex=r"\frac{dQ}{dP}\bigg|_{\mathcal{F}_T} = \exp\left(-\int_0^T \gamma_t dW_t^P - \frac{1}{2}\int_0^T \gamma_t^2 dt\right)",
        ascii="(dQ)/(dP)|_F_T = (-int_0^T gamma_t dW_t^P - (1)/(2)int_0^T gamma_t^2 dt )",
        method="Girsanov theorem for measure change. P (real-world) to Q (risk-neutral). Radon-Nikodym derivative. Foundation of risk-neutral pricing.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mean_variance_hedge": FormulaInfo(
        algorithm="mean_variance_hedge",
        latex=r"\min_\delta E[(V_T - \delta_T S_T)^2], \quad \delta^* = \frac{\text{Cov}(V_T, S_T)}{\text{Var}(S_T)}",
        ascii="_delta E[(V_T - delta_T S_T)^2], delta^* = Cov(V_T, S_T)Var(S_T)",
        method="Minimum variance hedge ratio. Regression-based: delta = Cov(V,S)/Var(S). Used when perfect replication impossible (incomplete markets, basis risk).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "xccy_basis_swap": FormulaInfo(
        algorithm="xccy_basis_swap",
        latex=r"V = \sum_i \delta_i^d (L_i^d + s) P^d(0,T_i) N_d - \sum_j \delta_j^f L_j^f P^f(0,T_j) N_f \cdot FX_0",
        ascii="V = sum_i delta_i^d (L_i^d + s) P^d(0,T_i) N_d - sum_j delta_j^f L_j^f P^f(0,T_j) N_f * FX_0",
        method="Cross-currency basis swap. Exchange floating rates in two currencies. Basis spread reflects relative funding costs. Notional exchange at start/end.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "fx_forward": FormulaInfo(
        algorithm="fx_forward",
        latex=r"F = S \cdot \frac{P_d(0,T)}{P_f(0,T)} = S \cdot e^{(r_d - r_f)T}",
        ascii="F = S * (P_d(0,T))/(P_f(0,T)) = S * e^(r_d - r_f)T",
        method="FX forward pricing via covered interest parity. F = S * P_domestic / P_foreign. Deviation = cross-currency basis. NDF for non-deliverable currencies.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "multi_curve_framework": FormulaInfo(
        algorithm="multi_curve_framework",
        latex=r"V = \sum_i \delta_i E^T[L(T_{i-1}, T_i)] P^{OIS}(0, T_i), \quad E^T[L] \neq \frac{1}{\delta}\left(\frac{P^L(0,T_{i-1})}{P^L(0,T_i)}-1\right) + \text{convexity adj}",
        ascii="V = sum_i delta_i E^T[L(T_i-1, T_i)] P^OIS(0, T_i), E^T[L] (1)/(delta) (P^L(0,T_i-1)P^L(0,T_i)-1 ) + convexity adj",
        method="Multi-curve framework (post-crisis). Separate curves per tenor (1M, 3M, 6M LIBOR/SOFR) + OIS discounting. Tenor basis spreads. Convexity adjustments.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    # --- Cryptography & Security (v1.2.2) ---

    "aes_128": FormulaInfo(
        algorithm="aes_128",
        latex=r"C = E_K(P) \text{ where } K \in \{0,1\}^{128}, \text{10 rounds, SubBytes-ShiftRows-MixColumns-AddRoundKey}",
        ascii="C = E_K(P) where K \0,1^128, 10 rounds, SubBytes-ShiftRows-MixColumns-AddRoundKey",
        method="AES-128 block cipher, 10 rounds, 128-bit key",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_192": FormulaInfo(
        algorithm="aes_192",
        latex=r"C = E_K(P) \text{ where } K \in \{0,1\}^{192}, \text{12 rounds}",
        ascii="C = E_K(P) where K \0,1^192, 12 rounds",
        method="AES-192 block cipher, 12 rounds, 192-bit key",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_256": FormulaInfo(
        algorithm="aes_256",
        latex=r"C = E_K(P) \text{ where } K \in \{0,1\}^{256}, \text{14 rounds}",
        ascii="C = E_K(P) where K \0,1^256, 14 rounds",
        method="AES-256 block cipher, 14 rounds, 256-bit key",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_gcm": FormulaInfo(
        algorithm="aes_gcm",
        latex=r"C = \text{GCTR}(K, J_0, P), \quad T = \text{GHASH}(H, A, C) \oplus E_K(J_0)",
        ascii="C = GCTR(K, J_0, P), T = GHASH(H, A, C) E_K(J_0)",
        method="AES in Galois/Counter Mode with authentication tag",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_ctr": FormulaInfo(
        algorithm="aes_ctr",
        latex=r"C_i = P_i \oplus E_K(\text{nonce} \| \text{counter}_i)",
        ascii="C_i = P_i E_K(nonce | counter_i)",
        method="AES in Counter mode",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_cbc": FormulaInfo(
        algorithm="aes_cbc",
        latex=r"C_i = E_K(P_i \oplus C_{i-1}), \quad C_0 = IV",
        ascii="C_i = E_K(P_i C_i-1), C_0 = IV",
        method="AES in Cipher Block Chaining mode",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_xts": FormulaInfo(
        algorithm="aes_xts",
        latex=r"C = E_{K_1}(P \oplus T) \oplus T, \quad T = E_{K_2}(i) \otimes \alpha^j",
        ascii="C = E_K_1(P T) T, T = E_K_2(i) alpha^j",
        method="AES in XEX-based Tweaked-codebook mode with ciphertext Stealing",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "chacha20": FormulaInfo(
        algorithm="chacha20",
        latex=r"\text{state} = \text{QR}^{20}(\sigma \| K \| \text{counter} \| \text{nonce}), \quad \text{QR}(a,b,c,d): a{+}{=}b; d{\oplus}{=}a; d{\lll}{=}16; \ldots",
        ascii="state = QR^20(sigma | K | counter | nonce), QR(a,b,c,d): a+=b; d=a; d=16;",
        method="ChaCha20 stream cipher, 20 rounds, 256-bit key",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "chacha20_poly1305": FormulaInfo(
        algorithm="chacha20_poly1305",
        latex=r"C = \text{ChaCha20}(K, N, P), \quad T = \text{Poly1305}(\text{otk}, \text{AAD} \| C)",
        ascii="C = ChaCha20(K, N, P), T = Poly1305(otk, AAD | C)",
        method="ChaCha20-Poly1305 AEAD construction (RFC 8439)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "des": FormulaInfo(
        algorithm="des",
        latex=r"C = IP^{-1}(\text{Feistel}^{16}(IP(P), K_{1..16}))",
        ascii="C = IP^-1(Feistel^16(IP(P), K_1..16))",
        method="Data Encryption Standard, 16 Feistel rounds, 56-bit effective key",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "triple_des": FormulaInfo(
        algorithm="triple_des",
        latex=r"C = E_{K_1}(D_{K_2}(E_{K_3}(P)))",
        ascii="C = E_K_1(D_K_2(E_K_3(P)))",
        method="Triple DES (3DES/TDES), encrypt-decrypt-encrypt with 2 or 3 keys",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "blowfish": FormulaInfo(
        algorithm="blowfish",
        latex=r"C = \text{Feistel}^{16}(P, P_0..P_{17}), \quad F(x) = ((S_1[a] + S_2[b]) \oplus S_3[c]) + S_4[d]",
        ascii="C = Feistel^16(P, P_0..P_17), F(x) = ((S_1[a] + S_2[b]) S_3[c]) + S_4[d]",
        method="Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "twofish": FormulaInfo(
        algorithm="twofish",
        latex=r"C = \text{Feistel}^{16}(P, K), \text{ MDS matrix + PHT + key-dependent S-boxes}",
        ascii="C = Feistel^16(P, K), MDS matrix + PHT + key-dependent S-boxes",
        method="Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "serpent": FormulaInfo(
        algorithm="serpent",
        latex=r"C = FP(\hat{R}_{31}(\ldots\hat{R}_0(IP(P), K)\ldots))",
        ascii="C = FP(R_31(R_0(IP(P), K)))",
        method="Serpent block cipher, 32 rounds, 128/192/256-bit key (AES finalist)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "camellia": FormulaInfo(
        algorithm="camellia",
        latex=r"C = \text{Feistel}^{18/24}(P, K), \text{ FL/FL}^{-1} \text{ every 6 rounds}",
        ascii="C = Feistel^18/24(P, K), FL/FL^-1 every 6 rounds",
        method="Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aria": FormulaInfo(
        algorithm="aria",
        latex=r"C = \text{SPN}^{12/14/16}(P, K), \text{ diffusion layer: 16x16 involutory binary matrix}",
        ascii="C = SPN^12/14/16(P, K), diffusion layer: 16x16 involutory binary matrix",
        method="ARIA block cipher, Korean standard (NSRI), 12/14/16 rounds",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sm4": FormulaInfo(
        algorithm="sm4",
        latex=r"C = R^{32}(P, rk_0..rk_{31}), \quad \tau(A) = (\text{Sbox}(a_0), \ldots), \quad L(B) = B \oplus (B\lll 2) \oplus (B\lll 10) \oplus (B\lll 18) \oplus (B\lll 24)",
        ascii="C = R^32(P, rk_0..rk_31), tau(A) = (Sbox(a_0), ), L(B) = B (B 2) (B 10) (B 18) (B 24)",
        method="SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rc4": FormulaInfo(
        algorithm="rc4",
        latex=r"\text{KSA:} S[i] \leftrightarrow S[j], j=(j+S[i]+K[i\bmod l])\bmod 256; \quad \text{PRGA:} i{+}{+}, j{+}{=}S[i], \text{swap}, \text{output}=S[(S[i]+S[j])\bmod 256]",
        ascii="KSA: S[i] rightarrow S[j], j=(j+S[i]+K[i l]) 256; PRGA: i++, j+=S[i], swap, output=S[(S[i]+S[j]) 256]",
        method="RC4 (ARC4) stream cipher, variable key size",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rc5": FormulaInfo(
        algorithm="rc5",
        latex=r"A = ((A \oplus B) \lll B) + S[2i], \quad B = ((B \oplus A) \lll A) + S[2i+1]",
        ascii="A = ((A B) B) + S[2i], B = ((B A) A) + S[2i+1]",
        method="RC5 block cipher, data-dependent rotations, variable rounds/key/block",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rc6": FormulaInfo(
        algorithm="rc6",
        latex=r"t = (B \times (2B+1)) \lll \log_2 w, \quad u = (D \times (2D+1)) \lll \log_2 w",
        ascii="t = (B x (2B+1)) _2 w, u = (D x (2D+1)) _2 w",
        method="RC6 block cipher, AES finalist, uses integer multiplication",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "tea": FormulaInfo(
        algorithm="tea",
        latex=r"\text{sum} += \delta; \quad v_0 += ((v_1 \ll 4)+K_0) \oplus (v_1+\text{sum}) \oplus ((v_1 \gg 5)+K_1)",
        ascii="sum += delta; v_0 += ((v_1 4)+K_0) (v_1+sum) ((v_1 5)+K_1)",
        method="Tiny Encryption Algorithm, 64 rounds, 128-bit key, 64-bit block",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "xtea": FormulaInfo(
        algorithm="xtea",
        latex=r"v_0 += ((v_1\ll 4 \oplus v_1\gg 5) + v_1) \oplus (\text{sum} + K[\text{sum} \& 3])",
        ascii="v_0 += ((v_1 4 v_1 5) + v_1) (sum + K[sum & 3])",
        method="Extended TEA (XTEA), fixes TEA key schedule weakness",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cast5": FormulaInfo(
        algorithm="cast5",
        latex=r"C = \text{Feistel}^{12/16}(P, K), \text{ 4 large S-boxes (8->32 bit)}",
        ascii="C = Feistel^12/16(P, K), 4 large S-boxes (8->32 bit)",
        method="CAST-128 (CAST5) block cipher, 12 or 16 Feistel rounds",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "idea": FormulaInfo(
        algorithm="idea",
        latex=r"\text{Operations:} \oplus, \boxplus_{2^{16}}, \odot_{2^{16}+1}",
        ascii="Operations: , _2^16, _2^16+1",
        method="International Data Encryption Algorithm, 8.5 rounds",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "salsa20": FormulaInfo(
        algorithm="salsa20",
        latex=r"\text{state} = \text{columnround}^{10}(\text{rowround}^{10}(\sigma \| K \| \text{nonce} \| \text{counter}))",
        ascii="state = columnround^10(rowround^10(sigma | K | nonce | counter))",
        method="Salsa20 stream cipher, 20 rounds, predecessor of ChaCha20",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gost_28147_89": FormulaInfo(
        algorithm="gost_28147_89",
        latex=r"C = \text{Feistel}^{32}(P, K), \quad f(x) = S(x \boxplus K_i) \lll 11",
        ascii="C = Feistel^32(P, K), f(x) = S(x K_i) 11",
        method="GOST 28147-89 (Magma) Russian block cipher, 32 Feistel rounds",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kuznyechik": FormulaInfo(
        algorithm="kuznyechik",
        latex=r"C = \text{SPN}^{10}(P, K), \quad L(x) = l^{16}(x), \quad l: \text{GF}(2^8) \text{ multiplication}",
        ascii="C = SPN^10(P, K), L(x) = l^16(x), l: GF(2^8) multiplication",
        method="Kuznyechik (GOST R 34.12-2015), modern Russian block cipher",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rsa_pkcs1_v15": FormulaInfo(
        algorithm="rsa_pkcs1_v15",
        latex=r"C = M^e \bmod n, \quad M = C^d \bmod n, \quad ed \equiv 1 \pmod{\phi(n)}",
        ascii="C = M^e n, M = C^d n, ed 1 phi(n)",
        method="RSA with PKCS#1 v1.5 padding",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rsa_oaep": FormulaInfo(
        algorithm="rsa_oaep",
        latex=r"\text{OAEP:} \quad \text{maskedSeed} = \text{seed} \oplus \text{MGF1}(\text{maskedDB}), \quad \text{EM} = 0x00 \| \text{maskedSeed} \| \text{maskedDB}",
        ascii="OAEP: maskedSeed = seed MGF1(maskedDB), EM = 0x00 | maskedSeed | maskedDB",
        method="RSA with Optimal Asymmetric Encryption Padding (OAEP)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "diffie_hellman": FormulaInfo(
        algorithm="diffie_hellman",
        latex=r"A = g^a \bmod p, \quad B = g^b \bmod p, \quad K = B^a = A^b = g^{ab} \bmod p",
        ascii="A = g^a p, B = g^b p, K = B^a = A^b = g^ab p",
        method="Diffie-Hellman key exchange over finite field",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ecdh": FormulaInfo(
        algorithm="ecdh",
        latex=r"Q_A = d_A \cdot G, \quad K = d_A \cdot Q_B = d_B \cdot Q_A",
        ascii="Q_A = d_A * G, K = d_A * Q_B = d_B * Q_A",
        method="Elliptic Curve Diffie-Hellman key exchange",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "elgamal": FormulaInfo(
        algorithm="elgamal",
        latex=r"C = (g^k \bmod p, \; M \cdot y^k \bmod p), \quad y = g^x \bmod p",
        ascii="C = (g^k p, M * y^k p), y = g^x p",
        method="ElGamal encryption scheme",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dsa": FormulaInfo(
        algorithm="dsa",
        latex=r"r = (g^k \bmod p) \bmod q, \quad s = k^{-1}(H(m) + xr) \bmod q",
        ascii="r = (g^k p) q, s = k^-1(H(m) + xr) q",
        method="Digital Signature Algorithm (DSA)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ecdsa": FormulaInfo(
        algorithm="ecdsa",
        latex=r"r = (k \cdot G)_x \bmod n, \quad s = k^{-1}(e + rd) \bmod n",
        ascii="r = (k * G)_x n, s = k^-1(e + rd) n",
        method="Elliptic Curve Digital Signature Algorithm",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ed25519": FormulaInfo(
        algorithm="ed25519",
        latex=r"R = rB, \quad S = r + H(R \| A \| M) \cdot a \pmod{\ell}, \quad \ell = 2^{252} + 27742317777372353535851937790883648493",
        ascii="R = rB, S = r + H(R | A | M) * a , = 2^252 + 27742317777372353535851937790883648493",
        method="Ed25519 signature scheme (EdDSA on Curve25519)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ed448": FormulaInfo(
        algorithm="ed448",
        latex=r"R = rB, \quad S = r + H(R \| A \| M) \cdot a \pmod{\ell}",
        ascii="R = rB, S = r + H(R | A | M) * a",
        method="Ed448 signature scheme (EdDSA on Curve448-Goldilocks)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "x25519": FormulaInfo(
        algorithm="x25519",
        latex=r"Q = \text{scalar\_mult}(k, P) \text{ on Montgomery curve } y^2 = x^3 + 486662x^2 + x",
        ascii="Q = scalar_mult(k, P) on Montgomery curve y^2 = x^3 + 486662x^2 + x",
        method="X25519 ECDH key exchange (Curve25519 Montgomery form)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sm2": FormulaInfo(
        algorithm="sm2",
        latex=r"C = (C_1 \| C_3 \| C_2), \quad C_1 = kG, \quad C_2 = M \oplus \text{KDF}(kP_B), \quad C_3 = \text{SM3}(x_2 \| M \| y_2)",
        ascii="C = (C_1 | C_3 | C_2), C_1 = kG, C_2 = M KDF(kP_B), C_3 = SM3(x_2 | M | y_2)",
        method="SM2 Chinese national elliptic curve algorithm",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha1": FormulaInfo(
        algorithm="sha1",
        latex=r"H_0=\text{0x67452301}, H_1=\text{0xEFCDAB89}, \ldots, \quad f_t, K_t \text{ for 80 rounds}",
        ascii="H_0=0x67452301, H_1=0xEFCDAB89, , f_t, K_t for 80 rounds",
        method="SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha256": FormulaInfo(
        algorithm="sha256",
        latex=r"H_0^{(0)}=\text{0x6A09E667}, \ldots, \quad \Sigma_0, \Sigma_1, \sigma_0, \sigma_1, Ch, Maj \text{ for 64 rounds}",
        ascii="H_0^(0)=0x6A09E667, , _0, _1, sigma_0, sigma_1, Ch, Maj for 64 rounds",
        method="SHA-256 hash function, 64 rounds, 256-bit digest",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha384": FormulaInfo(
        algorithm="sha384",
        latex=r"\text{SHA-512 truncated to 384 bits with different IV}",
        ascii="SHA-512 truncated to 384 bits with different IV",
        method="SHA-384 hash function (SHA-512 with different IV, truncated output)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha512": FormulaInfo(
        algorithm="sha512",
        latex=r"H_0^{(0)}=\text{0x6A09E667F3BCC908}, \ldots, \quad 80 \text{ rounds with 64-bit words}",
        ascii="H_0^(0)=0x6A09E667F3BCC908, , 80 rounds with 64-bit words",
        method="SHA-512 hash function, 80 rounds, 512-bit digest",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha3_keccak": FormulaInfo(
        algorithm="sha3_keccak",
        latex=r"f = \iota \circ \chi \circ \pi \circ \rho \circ \theta, \quad \text{state: } 5 \times 5 \times 64 = 1600 \text{ bits, 24 rounds}",
        ascii="f = iota chi pi rho theta, state: 5 x 5 x 64 = 1600 bits, 24 rounds",
        method="SHA-3 (Keccak) sponge-based hash family, 24 rounds",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "md5": FormulaInfo(
        algorithm="md5",
        latex=r"a_0=\text{0x67452301}, b_0=\text{0xEFCDAB89}, c_0=\text{0x98BADCFE}, d_0=\text{0x10325476}, \quad T_i = \lfloor 2^{32} |\sin(i+1)| \rfloor",
        ascii="a_0=0x67452301, b_0=0xEFCDAB89, c_0=0x98BADCFE, d_0=0x10325476, T_i = 2^32 |(i+1)|",
        method="MD5 hash function, 64 rounds, 128-bit digest (BROKEN)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "md4": FormulaInfo(
        algorithm="md4",
        latex=r"\text{Same init as MD5}, \quad \sqrt{2} \rightarrow \text{0x5A827999}, \quad \sqrt{3} \rightarrow \text{0x6ED9EBA1}",
        ascii="Same init as MD5, sqrt(2) arrow 0x5A827999, sqrt(3) arrow 0x6ED9EBA1",
        method="MD4 hash function, predecessor of MD5 (BROKEN)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "blake2b": FormulaInfo(
        algorithm="blake2b",
        latex=r"\text{IV from SHA-512}, \quad G(v, a, b, c, d, x, y): \text{mixing with rotations } 32, 24, 16, 63",
        ascii="IV from SHA-512, G(v, a, b, c, d, x, y): mixing with rotations 32, 24, 16, 63",
        method="BLAKE2b hash, up to 512-bit digest, optimized for 64-bit platforms",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "blake2s": FormulaInfo(
        algorithm="blake2s",
        latex=r"\text{IV from SHA-256}, \quad G: \text{rotations } 16, 12, 8, 7",
        ascii="IV from SHA-256, G: rotations 16, 12, 8, 7",
        method="BLAKE2s hash, up to 256-bit digest, optimized for 32-bit platforms",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "blake3": FormulaInfo(
        algorithm="blake3",
        latex=r"\text{Merkle tree of BLAKE2s-like compressions}, \quad \text{IV from SHA-256}",
        ascii="Merkle tree of BLAKE2s-like compressions, IV from SHA-256",
        method="BLAKE3 hash, Merkle tree parallelizable, variable-length output",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ripemd160": FormulaInfo(
        algorithm="ripemd160",
        latex=r"H_0=\text{0x67452301}, \ldots, \quad \text{two parallel Feistel chains, 80 rounds each}",
        ascii="H_0=0x67452301, , two parallel Feistel chains, 80 rounds each",
        method="RIPEMD-160 hash, 160-bit, used in Bitcoin address generation",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "whirlpool": FormulaInfo(
        algorithm="whirlpool",
        latex=r"\text{Miyaguchi-Preneel with 10-round AES-like block cipher on 512-bit state}",
        ascii="Miyaguchi-Preneel with 10-round AES-like block cipher on 512-bit state",
        method="Whirlpool hash, 512-bit digest, AES-like internal structure",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sm3": FormulaInfo(
        algorithm="sm3",
        latex=r"\text{Merkle-Damgard, 64 rounds}, \quad IV = \text{0x7380166F 0x4914B2B9} \ldots",
        ascii="Merkle-Damgard, 64 rounds, IV = 0x7380166F 0x4914B2B9",
        method="SM3 Chinese national hash standard, 64 rounds, 256-bit",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "pbkdf2": FormulaInfo(
        algorithm="pbkdf2",
        latex=r"DK = T_1 \| T_2 \| \ldots, \quad T_i = U_1 \oplus U_2 \oplus \ldots \oplus U_c, \quad U_1 = \text{PRF}(P, S \| \text{INT}(i))",
        ascii="DK = T_1 | T_2 | , T_i = U_1 U_2 U_c, U_1 = PRF(P, S | INT(i))",
        method="Password-Based Key Derivation Function 2",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bcrypt": FormulaInfo(
        algorithm="bcrypt",
        latex=r"\text{EksBlowfishSetup}(\text{cost}, \text{salt}, \text{password}), \quad \text{then 64x encrypt } \text{\"OrpheanBeholderScryDoubt\"}",
        ascii="EksBlowfishSetup(cost, salt, password), then 64x encrypt \"OrpheanBeholderScryDoubt\"",
        method="bcrypt password hashing (Blowfish-based)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "scrypt": FormulaInfo(
        algorithm="scrypt",
        latex=r"B_i = \text{PBKDF2}(P, S, 1), \quad V_j = \text{BlockMix}^N, \quad \text{memory-hard sequential access}",
        ascii="B_i = PBKDF2(P, S, 1), V_j = BlockMix^N, memory-hard sequential access",
        method="scrypt memory-hard password KDF",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "argon2": FormulaInfo(
        algorithm="argon2",
        latex=r"\text{Memory-hard: } m \text{ KiB blocks}, t \text{ passes}, p \text{ lanes}",
        ascii="Memory-hard: m KiB blocks, t passes, p lanes",
        method="Argon2 memory-hard password hashing (PHC winner)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hkdf": FormulaInfo(
        algorithm="hkdf",
        latex=r"\text{PRK} = \text{HMAC}(\text{salt}, \text{IKM}), \quad \text{OKM} = T_1 \| T_2 \| \ldots, \quad T_i = \text{HMAC}(\text{PRK}, T_{i-1} \| \text{info} \| i)",
        ascii="PRK = HMAC(salt, IKM), OKM = T_1 | T_2 | , T_i = HMAC(PRK, T_i-1 | info | i)",
        method="HMAC-based Key Derivation Function (RFC 5869)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hmac": FormulaInfo(
        algorithm="hmac",
        latex=r"\text{HMAC}(K, m) = H((K' \oplus \text{opad}) \| H((K' \oplus \text{ipad}) \| m))",
        ascii="HMAC(K, m) = H((K' opad) | H((K' ipad) | m))",
        method="Hash-based Message Authentication Code",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cmac": FormulaInfo(
        algorithm="cmac",
        latex=r"T = \text{AES}_{K}(M_n \oplus \text{prev} \oplus K_1), \quad K_1 = L \cdot x \text{ in GF}(2^{128})",
        ascii="T = AES_K(M_n prev K_1), K_1 = L * x in GF(2^128)",
        method="Cipher-based Message Authentication Code (AES-CMAC)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gmac": FormulaInfo(
        algorithm="gmac",
        latex=r"T = \text{GHASH}(H, \text{AAD}) \oplus E_K(J_0)",
        ascii="T = GHASH(H, AAD) E_K(J_0)",
        method="Galois Message Authentication Code (GCM without encryption)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "poly1305": FormulaInfo(
        algorithm="poly1305",
        latex=r"\text{tag} = (\sum_{i=1}^{q} (c_i + 2^{128}) \cdot r^{q+1-i} + s) \bmod 2^{130} - 5) \bmod 2^{128}",
        ascii="tag = (sum_i=1^q (c_i + 2^128) * r^q+1-i + s) 2^130 - 5) 2^128",
        method="Poly1305 one-time authenticator",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "siphash": FormulaInfo(
        algorithm="siphash",
        latex=r"v_0 = k_0 \oplus \text{0x736f6d6570736575}, \ldots, \quad c \text{ compression + } d \text{ finalization rounds}",
        ascii="v_0 = k_0 0x736f6d6570736575, , c compression + d finalization rounds",
        method="SipHash-2-4 keyed hash (hash table DoS protection)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "crc32": FormulaInfo(
        algorithm="crc32",
        latex=r"\text{CRC}(M) = M(x) \cdot x^{32} \bmod G(x), \quad G(x) = x^{32} + x^{26} + x^{23} + \ldots + 1",
        ascii="CRC(M) = M(x) * x^32 G(x), G(x) = x^32 + x^26 + x^23 + + 1",
        method="CRC-32 cyclic redundancy check",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "crc16_ccitt": FormulaInfo(
        algorithm="crc16_ccitt",
        latex=r"G(x) = x^{16} + x^{12} + x^5 + 1",
        ascii="G(x) = x^16 + x^12 + x^5 + 1",
        method="CRC-16-CCITT checksum",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "adler32": FormulaInfo(
        algorithm="adler32",
        latex=r"A = 1 + \sum D_i \bmod 65521, \quad B = \sum A_i \bmod 65521, \quad \text{Adler32} = B \cdot 65536 + A",
        ascii="A = 1 + sum D_i 65521, B = sum A_i 65521, Adler32 = B * 65536 + A",
        method="Adler-32 checksum (used in zlib)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "tls12_handshake": FormulaInfo(
        algorithm="tls12_handshake",
        latex=r"\text{ClientHello} \rightarrow \text{ServerHello} \rightarrow \text{Certificate} \rightarrow \text{KeyExchange} \rightarrow \text{Finished}",
        ascii="ClientHello arrow ServerHello arrow Certificate arrow KeyExchange arrow Finished",
        method="TLS 1.2 handshake protocol",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "tls13_handshake": FormulaInfo(
        algorithm="tls13_handshake",
        latex=r"\text{1-RTT:} \text{ClientHello}+\text{key\_share} \rightarrow \text{ServerHello}+\text{EncryptedExtensions}+\text{Finished}",
        ascii="1-RTT: ClientHello+key_share arrow ServerHello+EncryptedExtensions+Finished",
        method="TLS 1.3 handshake protocol (RFC 8446)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "jwt": FormulaInfo(
        algorithm="jwt",
        latex=r"\text{JWT} = \text{Base64url}(\text{header}) \cdot \text{Base64url}(\text{payload}) \cdot \text{Base64url}(\text{signature})",
        ascii="JWT = Base64url(header) * Base64url(payload) * Base64url(signature)",
        method="JSON Web Token (RFC 7519)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kerberos": FormulaInfo(
        algorithm="kerberos",
        latex=r"\text{AS-REQ} \rightarrow \text{AS-REP}(\text{TGT}) \rightarrow \text{TGS-REQ} \rightarrow \text{TGS-REP}(\text{ticket}) \rightarrow \text{AP-REQ}",
        ascii="AS-REQ arrow AS-REP(TGT) arrow TGS-REQ arrow TGS-REP(ticket) arrow AP-REQ",
        method="Kerberos v5 authentication protocol",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ipsec_esp": FormulaInfo(
        algorithm="ipsec_esp",
        latex=r"\text{ESP} = \text{SPI} \| \text{SeqNum} \| E_K(\text{Payload} \| \text{Padding} \| \text{PadLen} \| \text{NextHdr}) \| \text{ICV}",
        ascii="ESP = SPI | SeqNum | E_K(Payload | Padding | PadLen | NextHdr) | ICV",
        method="IPsec Encapsulating Security Payload",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ipsec_ah": FormulaInfo(
        algorithm="ipsec_ah",
        latex=r"\text{AH} = \text{NextHdr} \| \text{PayloadLen} \| \text{SPI} \| \text{SeqNum} \| \text{ICV}",
        ascii="AH = NextHdr | PayloadLen | SPI | SeqNum | ICV",
        method="IPsec Authentication Header",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ikev2": FormulaInfo(
        algorithm="ikev2",
        latex=r"\text{IKE\_SA\_INIT} \rightarrow \text{IKE\_AUTH} \rightarrow \text{CREATE\_CHILD\_SA}",
        ascii="IKE_SA_INIT arrow IKE_AUTH arrow CREATE_CHILD_SA",
        method="IKEv2 key exchange for IPsec",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "wireguard_noise": FormulaInfo(
        algorithm="wireguard_noise",
        latex=r"\text{Noise\_IKpsk2:} \quad \text{handshake} = \text{ChaCha20-Poly1305}(\text{BLAKE2s-KDF}(\ldots))",
        ascii="Noise_IKpsk2: handshake = ChaCha20-Poly1305(BLAKE2s-KDF())",
        method="WireGuard VPN (Noise IKpsk2 protocol)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ssh_key_exchange": FormulaInfo(
        algorithm="ssh_key_exchange",
        latex=r"K = \text{DH/ECDH}(e, f), \quad H = \text{hash}(V_C \| V_S \| I_C \| I_S \| K_S \| e \| f \| K)",
        ascii="K = DH/ECDH(e, f), H = hash(V_C | V_S | I_C | I_S | K_S | e | f | K)",
        method="SSH key exchange protocol",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "vm_detection_timing": FormulaInfo(
        algorithm="vm_detection_timing",
        latex=r"\Delta t = \text{RDTSC}_{\text{after}} - \text{RDTSC}_{\text{before}}",
        ascii="t = RDTSC_after - RDTSC_before",
        method="VM/debugger detection via timing side channels",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "opaque_predicate": FormulaInfo(
        algorithm="opaque_predicate",
        latex=r"x^2 + x \equiv 0 \pmod{2} \quad \text{(always true)}",
        ascii="x^2 + x 0 2 (always true)",
        method="Opaque predicate obfuscation",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "string_encryption": FormulaInfo(
        algorithm="string_encryption",
        latex=r"s_i = c_i \oplus k_{i \bmod |k|}",
        ascii="s_i = c_i k_i |k|",
        method="String encryption/obfuscation patterns",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "clmul": FormulaInfo(
        algorithm="clmul",
        latex=r"\text{PCLMULQDQ:} \quad c(x) = a(x) \cdot b(x) \text{ in GF}(2^n)",
        ascii="PCLMULQDQ: c(x) = a(x) * b(x) in GF(2^n)",
        method="Carry-less multiplication (CLMUL) for GF(2^n)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "curve25519_field_ops": FormulaInfo(
        algorithm="curve25519_field_ops",
        latex=r"p = 2^{255} - 19, \quad y^2 = x^3 + 486662x^2 + x",
        ascii="p = 2^255 - 19, y^2 = x^3 + 486662x^2 + x",
        method="Curve25519 field arithmetic primitives",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "secp256k1": FormulaInfo(
        algorithm="secp256k1",
        latex=r"y^2 = x^3 + 7 \pmod{p}, \quad p = 2^{256} - 2^{32} - 977",
        ascii="y^2 = x^3 + 7 p, p = 2^256 - 2^32 - 977",
        method="secp256k1 elliptic curve (Bitcoin)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "secp256r1_p256": FormulaInfo(
        algorithm="secp256r1_p256",
        latex=r"y^2 = x^3 - 3x + b \pmod{p}, \quad p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1",
        ascii="y^2 = x^3 - 3x + b p, p = 2^256 - 2^224 + 2^192 + 2^96 - 1",
        method="NIST P-256 (secp256r1/prime256v1) elliptic curve",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "secp384r1_p384": FormulaInfo(
        algorithm="secp384r1_p384",
        latex=r"y^2 = x^3 - 3x + b \pmod{p}, \quad p = 2^{384} - 2^{128} - 2^{96} + 2^{32} - 1",
        ascii="y^2 = x^3 - 3x + b p, p = 2^384 - 2^128 - 2^96 + 2^32 - 1",
        method="NIST P-384 (secp384r1) elliptic curve",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "montgomery_multiplication": FormulaInfo(
        algorithm="montgomery_multiplication",
        latex=r"\text{MonPro}(a, b) = a \cdot b \cdot R^{-1} \bmod n, \quad R = 2^k",
        ascii="MonPro(a, b) = a * b * R^-1 n, R = 2^k",
        method="Montgomery modular multiplication",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "chinese_remainder_theorem": FormulaInfo(
        algorithm="chinese_remainder_theorem",
        latex=r"x \equiv a_i \pmod{m_i}, \quad x = \sum a_i M_i M_i^{-1} \bmod M",
        ascii="x a_i m_i, x = sum a_i M_i M_i^-1 M",
        method="Chinese Remainder Theorem (RSA-CRT optimization)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "fortuna_csprng": FormulaInfo(
        algorithm="fortuna_csprng",
        latex=r"\text{Generate:} C = E_K(C), \quad \text{Reseed:} K = \text{SHA-256}(K \| s)",
        ascii="Generate: C = E_K(C), Reseed: K = SHA-256(K | s)",
        method="Fortuna CSPRNG (Apple/FreeBSD random)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "chacha20_csprng": FormulaInfo(
        algorithm="chacha20_csprng",
        latex=r"\text{output} = \text{ChaCha20}(K, N, \text{counter}++)",
        ascii="output = ChaCha20(K, N, counter++)",
        method="ChaCha20-based CSPRNG",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "xorshift": FormulaInfo(
        algorithm="xorshift",
        latex=r"x \mathrel{\hat{}}= x \ll a; \quad x \mathrel{\hat{}}= x \gg b; \quad x \mathrel{\hat{}}= x \ll c",
        ascii="x = x a; x = x b; x = x c",
        method="XorShift family PRNG (NOT cryptographic)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha512_256": FormulaInfo(
        algorithm="sha512_256",
        latex=r"\text{SHA-512/256: SHA-512 with different IV, truncated to 256 bits}",
        ascii="SHA-512/256: SHA-512 with different IV, truncated to 256 bits",
        method="SHA-512/256 hash (SHA-512 with different IV, truncated)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "streebog": FormulaInfo(
        algorithm="streebog",
        latex=r"\text{GOST R 34.11-2012 (Streebog)}, \quad \text{12 rounds with 512-bit state}",
        ascii="GOST R 34.11-2012 (Streebog), 12 rounds with 512-bit state",
        method="Streebog (GOST R 34.11-2012) Russian hash standard",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "shake128": FormulaInfo(
        algorithm="shake128",
        latex=r"\text{SHAKE128}(M, d) = \text{Keccak}[256](M \| 1111, d)",
        ascii="SHAKE128(M, d) = Keccak[256](M | 1111, d)",
        method="SHAKE128 extendable output function (SHA-3 family)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "shake256": FormulaInfo(
        algorithm="shake256",
        latex=r"\text{SHAKE256}(M, d) = \text{Keccak}[512](M \| 1111, d)",
        ascii="SHAKE256(M, d) = Keccak[512](M | 1111, d)",
        method="SHAKE256 extendable output function (SHA-3 family)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "xchacha20_poly1305": FormulaInfo(
        algorithm="xchacha20_poly1305",
        latex=r"\text{subkey} = \text{HChaCha20}(K, N[0..15]), \quad C = \text{ChaCha20-Poly1305}(\text{subkey}, N[16..23], P)",
        ascii="subkey = HChaCha20(K, N[0..15]), C = ChaCha20-Poly1305(subkey, N[16..23], P)",
        method="XChaCha20-Poly1305 AEAD with extended nonce",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_siv": FormulaInfo(
        algorithm="aes_siv",
        latex=r"\text{IV} = \text{S2V}(K_1, \text{AAD}_1, \ldots, P), \quad C = \text{AES-CTR}(K_2, \text{IV}, P)",
        ascii="IV = S2V(K_1, AAD_1, , P), C = AES-CTR(K_2, IV, P)",
        method="AES-SIV nonce-misuse resistant AEAD (RFC 5297)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_ccm": FormulaInfo(
        algorithm="aes_ccm",
        latex=r"T = \text{CBC-MAC}(K, B_0 \| \text{AAD} \| P), \quad C = \text{CTR}(K, A_0, P) \| (T \oplus E_K(A_0))",
        ascii="T = CBC-MAC(K, B_0 | AAD | P), C = CTR(K, A_0, P) | (T E_K(A_0))",
        method="AES-CCM authenticated encryption",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aegis": FormulaInfo(
        algorithm="aegis",
        latex=r"\text{AEGIS-128L: 8 AES rounds per 256-bit message block}",
        ascii="AEGIS-128L: 8 AES rounds per 256-bit message block",
        method="AEGIS AEAD (AES-based, very fast)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ghash": FormulaInfo(
        algorithm="ghash",
        latex=r"\text{GHASH}(H, X) = X_m \cdot H^m \oplus \ldots \oplus X_1 \cdot H \quad \text{in GF}(2^{128})",
        ascii="GHASH(H, X) = X_m * H^m X_1 * H in GF(2^128)",
        method="GHASH universal hash function (used in GCM)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "chacha20_ietf": FormulaInfo(
        algorithm="chacha20_ietf",
        latex=r"\text{IETF variant: 32-bit counter + 96-bit nonce (vs original 64/64)}",
        ascii="IETF variant: 32-bit counter + 96-bit nonce (vs original 64/64)",
        method="ChaCha20-IETF with 96-bit nonce (RFC 8439)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_ecb": FormulaInfo(
        algorithm="aes_ecb",
        latex=r"C_i = E_K(P_i) \quad \text{(no chaining)}",
        ascii="C_i = E_K(P_i) (no chaining)",
        method="AES in Electronic Codebook mode (INSECURE)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_cfb": FormulaInfo(
        algorithm="aes_cfb",
        latex=r"C_i = P_i \oplus E_K(C_{i-1}), \quad C_0 = IV",
        ascii="C_i = P_i E_K(C_i-1), C_0 = IV",
        method="AES in Cipher Feedback mode",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_ofb": FormulaInfo(
        algorithm="aes_ofb",
        latex=r"O_i = E_K(O_{i-1}), \quad C_i = P_i \oplus O_i, \quad O_0 = IV",
        ascii="O_i = E_K(O_i-1), C_i = P_i O_i, O_0 = IV",
        method="AES in Output Feedback mode",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_key_wrap": FormulaInfo(
        algorithm="aes_key_wrap",
        latex=r"A = \text{0xA6A6A6A6A6A6A6A6}, \quad (A, R_n) = W^{-1}(C)",
        ascii="A = 0xA6A6A6A6A6A6A6A6, (A, R_n) = W^-1(C)",
        method="AES Key Wrap (RFC 3394)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rijndael_sbox_full": FormulaInfo(
        algorithm="rijndael_sbox_full",
        latex=r"S(x) = A \cdot x^{-1} + c \quad \text{in GF}(2^8), \quad A = \text{affine matrix}",
        ascii="S(x) = A * x^-1 + c in GF(2^8), A = affine matrix",
        method="AES/Rijndael S-box (full 256-byte lookup table)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rsa_key_generation": FormulaInfo(
        algorithm="rsa_key_generation",
        latex=r"n = p \cdot q, \quad \phi(n) = (p-1)(q-1), \quad d = e^{-1} \bmod \phi(n)",
        ascii="n = p * q, phi(n) = (p-1)(q-1), d = e^-1 phi(n)",
        method="RSA key pair generation",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "des_key_schedule": FormulaInfo(
        algorithm="des_key_schedule",
        latex=r"\text{PC-1} \rightarrow \text{left shifts} \rightarrow \text{PC-2} \times 16 \text{ subkeys}",
        ascii="PC-1 arrow left shifts arrow PC-2 x 16 subkeys",
        method="DES key schedule (PC-1, PC-2, rotations)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "aes_rcon": FormulaInfo(
        algorithm="aes_rcon",
        latex=r"\text{Rcon}[i] = [rc_i, 0, 0, 0], \quad rc_1 = 1, \quad rc_i = 2 \cdot rc_{i-1} \text{ in GF}(2^8)",
        ascii="Rcon[i] = [rc_i, 0, 0, 0], rc_1 = 1, rc_i = 2 * rc_i-1 in GF(2^8)",
        method="AES round constants (Rcon) for key expansion",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha256_k_constants": FormulaInfo(
        algorithm="sha256_k_constants",
        latex=r"K_i = \lfloor 2^{32} \cdot \text{frac}(\sqrt[3]{p_i}) \rfloor \quad \text{for first 64 primes}",
        ascii="K_i = 2^32 * frac([3]p_i) for first 64 primes",
        method="SHA-256 round constants K[0..63]",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "md5_t_table": FormulaInfo(
        algorithm="md5_t_table",
        latex=r"T[i] = \lfloor 2^{32} \cdot |\sin(i+1)| \rfloor",
        ascii="T[i] = 2^32 * |(i+1)|",
        method="MD5 sine-derived round constants T[1..64]",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "keccak_round_constants_full": FormulaInfo(
        algorithm="keccak_round_constants_full",
        latex=r"RC[i] = \bigoplus_{j=0}^{6} \text{rc}(j+7i) \cdot 2^{2^j-1}",
        ascii="RC[i] = _j=0^6 rc(j+7i) * 2^2^j-1",
        method="Keccak/SHA-3 all 24 round constants",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sha1_k_constants": FormulaInfo(
        algorithm="sha1_k_constants",
        latex=r"K = \{\lfloor 2^{30} \sqrt{2} \rfloor, \lfloor 2^{30} \sqrt{3} \rfloor, \lfloor 2^{30} \sqrt{5} \rfloor, \lfloor 2^{30} \sqrt{10} \rfloor\}",
        ascii="K = {2^30 sqrt(2), 2^30 sqrt(3), 2^30 sqrt(5), 2^30 sqrt(10)}",
        method="SHA-1 round constants K[0..3]",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "tls_prf": FormulaInfo(
        algorithm="tls_prf",
        latex=r"\text{PRF}(\text{secret}, \text{label}, \text{seed}) = \text{P\_SHA256}(\text{secret}, \text{label} \| \text{seed})",
        ascii="PRF(secret, label, seed) = P_SHA256(secret, label | seed)",
        method="TLS pseudo-random function",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "noise_protocol": FormulaInfo(
        algorithm="noise_protocol",
        latex=r"\text{Noise\_XX:} \quad \text{e, es, s, ss pattern with symmetric state}",
        ascii="Noise_XX: e, es, s, ss pattern with symmetric state",
        method="Noise Protocol Framework (used in WireGuard, Signal, etc.)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "signal_protocol": FormulaInfo(
        algorithm="signal_protocol",
        latex=r"\text{X3DH} + \text{Double Ratchet}",
        ascii="X3DH + Double Ratchet",
        method="Signal Protocol (X3DH + Double Ratchet)",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dilithium": FormulaInfo(
        algorithm="dilithium",
        latex=r"\text{Lattice-based signature: } z = y + cs, \quad \|z\|_\infty < \gamma_1 - \beta",
        ascii="Lattice-based signature: z = y + cs, |z|_infty < gamma_1 - beta",
        method="CRYSTALS-Dilithium / ML-DSA post-quantum signature",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kyber": FormulaInfo(
        algorithm="kyber",
        latex=r"\text{Lattice-based KEM: } c = (u, v), \quad u = A^T r + e_1, \quad v = t^T r + e_2 + \lceil q/2 \rceil m",
        ascii="Lattice-based KEM: c = (u, v), u = A^T r + e_1, v = t^T r + e_2 + q/2 m",
        method="CRYSTALS-Kyber / ML-KEM post-quantum key encapsulation",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    # --- Advanced Engineering (v1.2.2) ---

    "vof_volume_of_fluid": FormulaInfo(
        algorithm="vof_volume_of_fluid",
        latex=r"\frac{\partial \alpha}{\partial t} + \nabla \cdot (\alpha \mathbf{u}) = 0, \quad \rho = \alpha \rho_1 + (1-\alpha)\rho_2",
        ascii="(partial alpha)/(partial t) + nabla * (alpha u) = 0, rho = alpha rho_1 + (1-alpha)rho_2",
        method="Volume of Fluid method for tracking free surfaces and interfaces in multiphase flows. Alpha=1 for fluid 1, alpha=0 for fluid 2.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "level_set_method": FormulaInfo(
        algorithm="level_set_method",
        latex=r"\frac{\partial \phi}{\partial t} + \mathbf{u} \cdot \nabla \phi = 0, \quad |\nabla \phi| = 1 \text{ (reinitialization)}",
        ascii="(partial phi)/(partial t) + u * nabla phi = 0, |nabla phi| = 1 (reinitialization)",
        method="Level set method for interface tracking. Phi is a signed distance function; zero level set defines the interface.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "lattice_boltzmann": FormulaInfo(
        algorithm="lattice_boltzmann",
        latex=r"f_i(\mathbf{x}+\mathbf{e}_i \Delta t, t+\Delta t) - f_i(\mathbf{x},t) = -\frac{1}{\tau}(f_i - f_i^{eq}), \quad f_i^{eq} = w_i \rho \left[1 + \frac{\mathbf{e}_i \cdot \mathbf{u}}{c_s^2} + \frac{(\mathbf{e}_i \cdot \mathbf{u})^2}{2c_s^4} - \frac{\mathbf{u}\cdot\mathbf{u}}{2c_s^2}\right]",
        ascii="f_i(x+e_i t, t+ t) - f_i(x,t) = -(1)/(tau)(f_i - f_i^eq), f_i^eq = w_i rho [1 + e_i * uc_s^2 + (e_i * u)^22c_s^4 - u*u2c",
        method="Lattice Boltzmann Method with BGK collision operator. Solves NS equations via mesoscale particle distribution functions on a lattice.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "des_detached_eddy": FormulaInfo(
        algorithm="des_detached_eddy",
        latex=r"\tilde{d} = \min(d, C_{DES} \Delta), \quad \Delta = \max(\Delta x, \Delta y, \Delta z)",
        ascii="d = (d, C_DES ), = ( x, y, z)",
        method="Detached Eddy Simulation -- hybrid RANS/LES switching based on grid spacing vs wall distance.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "standard_k_epsilon": FormulaInfo(
        algorithm="standard_k_epsilon",
        latex=r"\nu_t = C_\mu \frac{k^2}{\epsilon}, \quad \frac{\partial k}{\partial t} + u_j \frac{\partial k}{\partial x_j} = P_k - \epsilon + \frac{\partial}{\partial x_j}\left[\left(\nu + \frac{\nu_t}{\sigma_k}\right)\frac{\partial k}{\partial x_j}\right]",
        ascii="nu_t = C_mu (k^2)/(epsilon), (partial k)/(partial t) + u_j (partial k)/(partial x_j) = P_k - epsilon + (partial)/(partia",
        method="Standard k-epsilon turbulence model (Launder & Spalding 1974). Two-equation RANS model.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rsm_reynolds_stress": FormulaInfo(
        algorithm="rsm_reynolds_stress",
        latex=r"\frac{\partial \overline{u_i' u_j'}}{\partial t} + C_{ij} = P_{ij} + D_{ij} - \epsilon_{ij} + \Pi_{ij} + \Omega_{ij}",
        ascii="partial u_i' u_j'partial t + C_ij = P_ij + D_ij - epsilon_ij + _ij + _ij",
        method="Reynolds Stress Model (LRR/SSG). Full second-moment closure, 7 transport equations.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "immersed_boundary_method": FormulaInfo(
        algorithm="immersed_boundary_method",
        latex=r"\mathbf{f}(\mathbf{x},t) = \int_{\Gamma} \mathbf{F}(s,t) \, \delta(\mathbf{x}-\mathbf{X}(s,t)) \, ds",
        ascii="f(x,t) = int_ F(s,t) delta(x-X(s,t)) ds",
        method="Immersed Boundary Method (Peskin). Couples Lagrangian structure to Eulerian fluid via regularized delta function.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "muscl_scheme": FormulaInfo(
        algorithm="muscl_scheme",
        latex=r"u_{i+1/2}^L = u_i + \frac{1}{4}\left[(1-\kappa)(u_i-u_{i-1}) + (1+\kappa)(u_{i+1}-u_i)\right]\phi(r)",
        ascii="u_i+1/2^L = u_i + (1)/(4) [(1-kappa)(u_i-u_i-1) + (1+kappa)(u_i+1-u_i) ]phi(r)",
        method="MUSCL (Monotone Upstream-centered Schemes for Conservation Laws) reconstruction with slope limiters.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "weno_scheme": FormulaInfo(
        algorithm="weno_scheme",
        latex=r"u_{i+1/2} = \sum_{k=0}^{r-1} \omega_k \hat{u}_{i+1/2}^{(k)}, \quad \omega_k = \frac{\alpha_k}{\sum \alpha_k}, \quad \alpha_k = \frac{d_k}{(\epsilon+\beta_k)^2}",
        ascii="u_i+1/2 = sum_k=0^r-1 omega_k u_i+1/2^(k), omega_k = (alpha_k)/(sum alpha_k), alpha_k = (d_k)/((epsilon+beta_k)^2)",
        method="WENO (Weighted Essentially Non-Oscillatory) scheme for high-order shock-capturing in compressible flows.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "roe_solver": FormulaInfo(
        algorithm="roe_solver",
        latex=r"\mathbf{F}_{i+1/2} = \frac{1}{2}(\mathbf{F}_L+\mathbf{F}_R) - \frac{1}{2}\sum_{k=1}^{m}|\tilde{\lambda}_k|\tilde{\alpha}_k \tilde{\mathbf{r}}_k",
        ascii="F_i+1/2 = (1)/(2)(F_L+F_R) - (1)/(2)sum_k=1^m|lambda_k|alpha_k r_k",
        method="Roe's approximate Riemann solver for Euler/NS equations. Uses Roe-averaged states for flux computation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hllc_solver": FormulaInfo(
        algorithm="hllc_solver",
        latex=r"\mathbf{F}^{HLLC} = \begin{cases} \mathbf{F}_L & S_L \geq 0 \\ \mathbf{F}_{*L} & S_L \leq 0 \leq S_* \\ \mathbf{F}_{*R} & S_* \leq 0 \leq S_R \\ \mathbf{F}_R & S_R \leq 0 \end{cases}",
        ascii="F^HLLC = cases F_L & S_L 0  F_*L & S_L 0 S_*  F_*R & S_* 0 S_R  F_R & S_R 0 cases",
        method="HLLC Riemann solver (Toro). Restores contact discontinuity missing in basic HLL. Three wave speeds: S_L, S_*, S_R.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mixed_up_formulation": FormulaInfo(
        algorithm="mixed_up_formulation",
        latex=r"\begin{bmatrix} \mathbf{K} & \mathbf{G} \\ \mathbf{G}^T & \mathbf{0} \end{bmatrix} \begin{bmatrix} \mathbf{u} \\ \mathbf{p} \end{bmatrix} = \begin{bmatrix} \mathbf{f} \\ \mathbf{0} \end{bmatrix}",
        ascii="bmatrix K & G  G^T & 0 bmatrix bmatrix u  p bmatrix = bmatrix f  0 bmatrix",
        method="Mixed u-p formulation for nearly incompressible elasticity. Displacement-pressure split avoids volumetric locking.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "b_bar_method": FormulaInfo(
        algorithm="b_bar_method",
        latex=r"\bar{\mathbf{B}} = \mathbf{B}_{dev} + \bar{\mathbf{B}}_{vol}, \quad \bar{\mathbf{B}}_{vol} = \frac{1}{V_e}\int_{\Omega_e} \mathbf{B}_{vol}\,d\Omega",
        ascii="B = B_dev + B_vol, B_vol = (1)/(V_e)int__e B_vol d",
        method="B-bar method (Hughes 1980). Replaces volumetric B-matrix with element-averaged value to prevent locking.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "reduced_integration_hourglass": FormulaInfo(
        algorithm="reduced_integration_hourglass",
        latex=r"\mathbf{K}_{stab} = \alpha \int_{\Omega} \boldsymbol{\gamma}^T \boldsymbol{\gamma}\,d\Omega, \quad \boldsymbol{\gamma} = \mathbf{h} - (\mathbf{h}^T \mathbf{b})\mathbf{b}",
        ascii="K_stab = alpha int_ gamma^T gamma d, gamma = h - (h^T b)b",
        method="Hourglass control for reduced-integration elements. Adds stabilization stiffness to suppress zero-energy modes.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mortar_contact": FormulaInfo(
        algorithm="mortar_contact",
        latex=r"\int_{\gamma_c} \lambda \cdot \delta g_N \, d\gamma = 0, \quad g_N = (\mathbf{x}^{(1)} - \mathbf{x}^{(2)}) \cdot \mathbf{n}",
        ascii="int_gamma_c lambda * delta g_N dgamma = 0, g_N = (x^(1) - x^(2)) * n",
        method="Mortar contact method. Enforces contact constraints via Lagrange multipliers on non-matching meshes.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "xfem_extended_fem": FormulaInfo(
        algorithm="xfem_extended_fem",
        latex=r"\mathbf{u}^h(\mathbf{x}) = \sum_i N_i(\mathbf{x})\mathbf{u}_i + \sum_j N_j(\mathbf{x})H(\mathbf{x})\mathbf{a}_j + \sum_k N_k(\mathbf{x})\sum_{l=1}^{4}F_l(\mathbf{x})\mathbf{b}_k^l",
        ascii="u^h(x) = sum_i N_i(x)u_i + sum_j N_j(x)H(x)a_j + sum_k N_k(x)sum_l=1^4F_l(x)b_k^l",
        method="Extended Finite Element Method (XFEM). Enriches standard FE space with Heaviside and crack-tip functions for fracture.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cohesive_zone_model": FormulaInfo(
        algorithm="cohesive_zone_model",
        latex=r"T_n = \sigma_{max} \frac{\delta_n}{\delta_c} \exp\left(-\frac{\delta_n}{\delta_c}\right), \quad G_c = \int_0^{\infty} T_n(\delta_n)\,d\delta_n",
        ascii="T_n = sigma_max (delta_n)/(delta_c) (-(delta_n)/(delta_c) ), G_c = int_0^infty T_n(delta_n) ddelta_n",
        method="Cohesive zone model for fracture/delamination. Traction-separation law relates interfacial tractions to opening displacements.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "phase_field_fracture": FormulaInfo(
        algorithm="phase_field_fracture",
        latex=r"\Psi = \int_{\Omega}\left[(1-d)^2 \psi_0^+(\boldsymbol{\varepsilon}) + \psi_0^-(\boldsymbol{\varepsilon})\right]d\Omega + G_c\int_{\Omega}\left[\frac{d^2}{2l_0}+\frac{l_0}{2}|\nabla d|^2\right]d\Omega",
        ascii="= int_ [(1-d)^2 psi_0^+() + psi_0^-() ]d + G_cint_ [(d^2)/(2l_0)+(l_0)/(2)|nabla d|^2 ]d",
        method="Phase-field fracture model (AT2 formulation). Regularizes sharp crack with diffuse damage field d. l_0 is length scale parameter.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "neo_hookean": FormulaInfo(
        algorithm="neo_hookean",
        latex=r"W = \frac{\mu}{2}(\bar{I}_1 - 3) + \frac{K}{2}(J-1)^2, \quad \mathbf{S} = 2\frac{\partial W}{\partial \mathbf{C}}",
        ascii="W = (mu)/(2)(I_1 - 3) + (K)/(2)(J-1)^2, S = 2(partial W)/(partial C)",
        method="Neo-Hookean hyperelastic model. Simplest incompressible hyperelastic law. mu=shear modulus, K=bulk modulus.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mooney_rivlin": FormulaInfo(
        algorithm="mooney_rivlin",
        latex=r"W = C_{10}(\bar{I}_1-3) + C_{01}(\bar{I}_2-3) + \frac{K}{2}(J-1)^2",
        ascii="W = C_10(I_1-3) + C_01(I_2-3) + (K)/(2)(J-1)^2",
        method="Mooney-Rivlin hyperelastic model. Two-parameter model for moderate strains in rubber-like materials.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ogden_model": FormulaInfo(
        algorithm="ogden_model",
        latex=r"W = \sum_{p=1}^{N} \frac{\mu_p}{\alpha_p}(\bar{\lambda}_1^{\alpha_p}+\bar{\lambda}_2^{\alpha_p}+\bar{\lambda}_3^{\alpha_p}-3)",
        ascii="W = sum_p=1^N (mu_p)/(alpha_p)(lambda_1^alpha_p+lambda_2^alpha_p+lambda_3^alpha_p-3)",
        method="Ogden hyperelastic model. N-term model using principal stretches, fits rubber data over large strain range.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "arruda_boyce": FormulaInfo(
        algorithm="arruda_boyce",
        latex=r"W = \mu \sum_{i=1}^{5} \frac{C_i}{\lambda_m^{2i-2}}(\bar{I}_1^i - 3^i), \quad C_1=\tfrac{1}{2},\;C_2=\tfrac{1}{20},\;C_3=\tfrac{11}{1050},\;C_4=\tfrac{19}{7000},\;C_5=\tfrac{519}{673750}",
        ascii="W = mu sum_i=1^5 (C_i)/(lambda_m^2i-2)(I_1^i - 3^i), C_1=12, C_2=120, C_3=111050, C_4=197000, C_5=519673750",
        method="Arruda-Boyce eight-chain hyperelastic model. Micromechanically motivated, uses chain locking stretch lambda_m.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "von_mises_plasticity": FormulaInfo(
        algorithm="von_mises_plasticity",
        latex=r"f(\boldsymbol{\sigma}) = \sqrt{\frac{3}{2}\mathbf{s}:\mathbf{s}} - \sigma_y(\bar{\varepsilon}^p) \leq 0, \quad \dot{\boldsymbol{\varepsilon}}^p = \dot{\gamma}\frac{\partial f}{\partial \boldsymbol{\sigma}}",
        ascii="f(sigma) = sqrt((3)/(2)s):s - sigma_y(^p) 0, ^p = gamma(partial f)/(partial sigma)",
        method="von Mises (J2) plasticity with associative flow rule and isotropic hardening. Radial return mapping algorithm.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "drucker_prager_plasticity": FormulaInfo(
        algorithm="drucker_prager_plasticity",
        latex=r"f = q + p\tan\beta - d = 0, \quad q = \sqrt{3J_2}, \quad p = \frac{1}{3}\text{tr}(\boldsymbol{\sigma})",
        ascii="f = q + p - d = 0, q = sqrt(3J_2), p = (1)/(3)tr(sigma)",
        method="Drucker-Prager yield criterion. Pressure-dependent plasticity for soils, concrete, granular materials.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cam_clay": FormulaInfo(
        algorithm="cam_clay",
        latex=r"f = q^2 + M^2 p(p - p_c) = 0, \quad \dot{p}_c = \frac{1+e_0}{\lambda-\kappa}p_c \dot{\varepsilon}_v^p",
        ascii="f = q^2 + M^2 p(p - p_c) = 0, p_c = (1+e_0)/(lambda-kappa)p_c _v^p",
        method="Modified Cam-Clay model for soil. Elliptical yield surface in p-q space with hardening linked to plastic volumetric strain.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "norton_creep": FormulaInfo(
        algorithm="norton_creep",
        latex=r"\dot{\varepsilon}_{cr} = A \sigma^n \exp\left(-\frac{Q}{RT}\right)",
        ascii="_cr = A sigma^n (-(Q)/(RT) )",
        method="Norton power-law creep model. Steady-state creep rate is power function of stress with Arrhenius temperature dependence.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "pid_controller": FormulaInfo(
        algorithm="pid_controller",
        latex=r"u(t) = K_p e(t) + K_i \int_0^t e(\tau)\,d\tau + K_d \frac{de(t)}{dt}",
        ascii="u(t) = K_p e(t) + K_i int_0^t e(tau) dtau + K_d (de(t))/(dt)",
        method="PID (Proportional-Integral-Derivative) controller. Most widely used feedback controller in industrial automation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "lqr_controller": FormulaInfo(
        algorithm="lqr_controller",
        latex=r"J = \int_0^{\infty}(\mathbf{x}^T\mathbf{Q}\mathbf{x} + \mathbf{u}^T\mathbf{R}\mathbf{u})\,dt, \quad \mathbf{u} = -\mathbf{K}\mathbf{x}, \quad \mathbf{K} = \mathbf{R}^{-1}\mathbf{B}^T\mathbf{P}, \quad \mathbf{A}^T\mathbf{P}+\mathbf{P}\mathbf{A}-\mathbf{P}\mathbf{B}\mathbf{R}^{-1}\mathbf{B}^T\mathbf{P}+\mathbf{Q}=0",
        ascii="J = int_0^infty(x^TQx + u^TRu) dt, u = -Kx, K = R^-1B^TP, A^TP+PA-PBR^-1B^TP+Q=0",
        method="Linear Quadratic Regulator. Optimal state feedback via Algebraic Riccati Equation (ARE). Minimizes quadratic cost.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kalman_filter": FormulaInfo(
        algorithm="kalman_filter",
        latex=r"\hat{\mathbf{x}}_{k|k-1} = \mathbf{F}_k \hat{\mathbf{x}}_{k-1|k-1} + \mathbf{B}_k \mathbf{u}_k, \quad \mathbf{P}_{k|k-1} = \mathbf{F}_k\mathbf{P}_{k-1|k-1}\mathbf{F}_k^T + \mathbf{Q}_k, \quad \mathbf{K}_k = \mathbf{P}_{k|k-1}\mathbf{H}_k^T(\mathbf{H}_k\mathbf{P}_{k|k-1}\mathbf{H}_k^T+\mathbf{R}_k)^{-1}",
        ascii="x_k|k-1 = F_k x_k-1|k-1 + B_k u_k, P_k|k-1 = F_kP_k-1|k-1F_k^T + Q_k, K_k = P_k|k-1H_k^T(H_kP_k|k-1H_k^T+R_k)^-1",
        method="Linear Kalman filter for optimal state estimation. Predict-update cycle with Kalman gain minimizing mean squared error.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "extended_kalman_filter": FormulaInfo(
        algorithm="extended_kalman_filter",
        latex=r"\hat{\mathbf{x}}_{k|k-1} = f(\hat{\mathbf{x}}_{k-1|k-1}, \mathbf{u}_k), \quad \mathbf{F}_k = \left.\frac{\partial f}{\partial \mathbf{x}}\right|_{\hat{\mathbf{x}}_{k-1|k-1}}, \quad \mathbf{H}_k = \left.\frac{\partial h}{\partial \mathbf{x}}\right|_{\hat{\mathbf{x}}_{k|k-1}}",
        ascii="x_k|k-1 = f(x_k-1|k-1, u_k), F_k = .(partial f)/(partial x) |_x_k-1|k-1, H_k = .(partial h)/(partial x) |_x_k|k-1",
        method="Extended Kalman Filter for nonlinear systems. Linearizes dynamics/observation via Jacobians at current estimate.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "unscented_kalman_filter": FormulaInfo(
        algorithm="unscented_kalman_filter",
        latex=r"\mathcal{X}_0 = \hat{\mathbf{x}}, \quad \mathcal{X}_i = \hat{\mathbf{x}} + \left(\sqrt{(n+\lambda)\mathbf{P}}\right)_i, \quad W_0^{(m)} = \frac{\lambda}{n+\lambda}, \quad W_i = \frac{1}{2(n+\lambda)}",
        ascii="X_0 = x, X_i = x + (sqrt((n+lambda)P) )_i, W_0^(m) = (lambda)/(n+lambda), W_i = (1)/(2(n+lambda))",
        method="Unscented Kalman Filter. Uses deterministic sigma points instead of Jacobians for nonlinear state estimation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mpc_model_predictive": FormulaInfo(
        algorithm="mpc_model_predictive",
        latex=r"\min_{\mathbf{u}_{0:N-1}} \sum_{k=0}^{N-1}\left[\|\mathbf{x}_k-\mathbf{x}_{ref}\|_Q^2 + \|\mathbf{u}_k\|_R^2\right] + \|\mathbf{x}_N-\mathbf{x}_{ref}\|_P^2 \quad \text{s.t. } \mathbf{x}_{k+1}=f(\mathbf{x}_k,\mathbf{u}_k)",
        ascii="_u_0:N-1 sum_k=0^N-1 [|x_k-x_ref|_Q^2 + |u_k|_R^2 ] + |x_N-x_ref|_P^2 s.t. x_k+1=f(x_k,u_k)",
        method="Model Predictive Control. Solves finite-horizon optimal control online at each timestep with constraints.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "luenberger_observer": FormulaInfo(
        algorithm="luenberger_observer",
        latex=r"\dot{\hat{\mathbf{x}}} = \mathbf{A}\hat{\mathbf{x}} + \mathbf{B}\mathbf{u} + \mathbf{L}(\mathbf{y} - \mathbf{C}\hat{\mathbf{x}})",
        ascii="x = Ax + Bu + L(y - Cx)",
        method="Luenberger state observer. Estimates full state from output measurements using observer gain matrix L.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "pole_placement": FormulaInfo(
        algorithm="pole_placement",
        latex=r"\det(s\mathbf{I} - \mathbf{A} + \mathbf{B}\mathbf{K}) = \prod_{i=1}^{n}(s-p_i)",
        ascii="(sI - A + BK) = prod_i=1^n(s-p_i)",
        method="Pole placement (eigenvalue assignment) via state feedback. Places closed-loop poles at desired locations.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bode_analysis": FormulaInfo(
        algorithm="bode_analysis",
        latex=r"|G(j\omega)| = 20\log_{10}|G(j\omega)|\;\text{dB}, \quad \angle G(j\omega) = \arctan\frac{\text{Im}(G(j\omega))}{\text{Re}(G(j\omega))}",
        ascii="|G(jomega)| = 20_10|G(jomega)| dB, G(jomega) = Im(G(jomega))Re(G(jomega))",
        method="Bode plot analysis. Magnitude and phase of transfer function vs frequency. Key for stability margin assessment.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "nyquist_analysis": FormulaInfo(
        algorithm="nyquist_analysis",
        latex=r"N = Z - P, \quad \text{where } N = \text{encirclements of } (-1,0)",
        ascii="N = Z - P, where N = encirclements of (-1,0)",
        method="Nyquist stability criterion. Number of encirclements of (-1,0) by G(jw) determines closed-loop stability.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "fft_cooley_tukey": FormulaInfo(
        algorithm="fft_cooley_tukey",
        latex=r"X[k] = \sum_{m=0}^{N/2-1}x[2m]W_{N/2}^{mk} + W_N^k\sum_{m=0}^{N/2-1}x[2m+1]W_{N/2}^{mk}, \quad W_N = e^{-j2\pi/N}",
        ascii="X[k] = sum_m=0^N/2-1x[2m]W_N/2^mk + W_N^ksum_m=0^N/2-1x[2m+1]W_N/2^mk, W_N = e^-j2pi/N",
        method="FFT Cooley-Tukey radix-2 DIT algorithm. O(N log N) complexity. Recursively splits DFT into even/odd sub-problems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dft_definition": FormulaInfo(
        algorithm="dft_definition",
        latex=r"X[k] = \sum_{n=0}^{N-1} x[n]\,e^{-j2\pi kn/N}, \quad x[n] = \frac{1}{N}\sum_{k=0}^{N-1} X[k]\,e^{j2\pi kn/N}",
        ascii="X[k] = sum_n=0^N-1 x[n] e^-j2pi kn/N, x[n] = (1)/(N)sum_k=0^N-1 X[k] e^j2pi kn/N",
        method="Discrete Fourier Transform and its inverse. Maps time-domain signal to frequency-domain representation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "parks_mcclellan": FormulaInfo(
        algorithm="parks_mcclellan",
        latex=r"\min_{a_k} \max_{\omega \in S} |W(\omega)[D(\omega)-H(\omega)]|, \quad H(\omega) = \sum_{k=0}^{M} a_k \cos(k\omega)",
        ascii="_a_k _omega S |W(omega)[D(omega)-H(omega)]|, H(omega) = sum_k=0^M a_k (komega)",
        method="Parks-McClellan (Remez exchange) algorithm for optimal equiripple FIR filter design. Minimax approximation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "butterworth_design": FormulaInfo(
        algorithm="butterworth_design",
        latex=r"|H(j\omega)|^2 = \frac{1}{1+(\omega/\omega_c)^{2N}}, \quad \text{poles: } s_k = \omega_c e^{j\pi(2k+N-1)/(2N)}",
        ascii="|H(jomega)|^2 = (1)/(1+(omega/omega_c)^2N), poles: s_k = omega_c e^jpi(2k+N-1)/(2N)",
        method="Butterworth filter design. Maximally flat magnitude response in passband. All-pole transfer function.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "chebyshev_filter": FormulaInfo(
        algorithm="chebyshev_filter",
        latex=r"|H(j\omega)|^2 = \frac{1}{1+\epsilon^2 T_N^2(\omega/\omega_c)}, \quad T_N(x) = \cos(N\arccos(x))",
        ascii="|H(jomega)|^2 = (1)/(1+epsilon^2 T_N^2(omega/omega_c)), T_N(x) = (N(x))",
        method="Chebyshev Type I filter. Equiripple in passband, monotonic in stopband. Sharper rolloff than Butterworth for same order.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "elliptic_filter": FormulaInfo(
        algorithm="elliptic_filter",
        latex=r"|H(j\omega)|^2 = \frac{1}{1+\epsilon^2 R_N^2(\omega/\omega_c)}, \quad R_N = \text{Chebyshev rational function}",
        ascii="|H(jomega)|^2 = (1)/(1+epsilon^2 R_N^2(omega/omega_c)), R_N = Chebyshev rational function",
        method="Elliptic (Cauer) filter. Equiripple in both passband and stopband. Steepest transition for given order.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hilbert_transform": FormulaInfo(
        algorithm="hilbert_transform",
        latex=r"\hat{x}(t) = \frac{1}{\pi}\text{P.V.}\int_{-\infty}^{\infty}\frac{x(\tau)}{t-\tau}\,d\tau, \quad z(t) = x(t) + j\hat{x}(t)",
        ascii="x(t) = (1)/(pi)P.V.int_-infty^infty(x(tau))/(t-tau) dtau, z(t) = x(t) + jx(t)",
        method="Hilbert transform. Produces analytic signal for envelope/instantaneous frequency extraction.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "wavelet_transform": FormulaInfo(
        algorithm="wavelet_transform",
        latex=r"W(a,b) = \frac{1}{\sqrt{|a|}}\int_{-\infty}^{\infty}x(t)\psi^*\!\left(\frac{t-b}{a}\right)dt, \quad \text{DWT: } c_{j,k} = \sum_n x[n]\tilde{\psi}_{j,k}[n]",
        ascii="W(a,b) = (1)/(sqrt(|a|))int_-infty^inftyx(t)psi^* ((t-b)/(a) )dt, DWT: c_j,k = sum_n x[n]psi_j,k[n]",
        method="Continuous/Discrete Wavelet Transform. Time-frequency analysis with adaptive resolution. CWT for analysis, DWT for compression.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "welch_psd": FormulaInfo(
        algorithm="welch_psd",
        latex=r"\hat{S}_{xx}(f) = \frac{1}{KLU}\sum_{k=0}^{K-1}\left|\sum_{n=0}^{L-1}w[n]x_k[n]e^{-j2\pi fn}\right|^2, \quad U = \frac{1}{L}\sum_{n=0}^{L-1}|w[n]|^2",
        ascii="S_xx(f) = (1)/(KLU)sum_k=0^K-1 |sum_n=0^L-1w[n]x_k[n]e^-j2pi fn |^2, U = (1)/(L)sum_n=0^L-1|w[n]|^2",
        method="Welch's method for PSD estimation. Averages modified periodograms of overlapping windowed segments.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dh_forward_kinematics": FormulaInfo(
        algorithm="dh_forward_kinematics",
        latex=r"\mathbf{T}_n^0 = \prod_{i=1}^{n} \mathbf{A}_i, \quad \mathbf{A}_i = \begin{bmatrix}c\theta_i & -s\theta_i c\alpha_i & s\theta_i s\alpha_i & a_i c\theta_i \\ s\theta_i & c\theta_i c\alpha_i & -c\theta_i s\alpha_i & a_i s\theta_i \\ 0 & s\alpha_i & c\alpha_i & d_i \\ 0 & 0 & 0 & 1\end{bmatrix}",
        ascii="T_n^0 = prod_i=1^n A_i, A_i = bmatrixctheta_i & -stheta_i calpha_i & stheta_i salpha_i & a_i ctheta_i  stheta_i & cthe",
        method="Denavit-Hartenberg forward kinematics. Chain of homogeneous transforms from base to end-effector using DH convention.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "inverse_kinematics_jacobian": FormulaInfo(
        algorithm="inverse_kinematics_jacobian",
        latex=r"\dot{\mathbf{x}} = \mathbf{J}(\mathbf{q})\dot{\mathbf{q}}, \quad \Delta\mathbf{q} = \mathbf{J}^{\dagger}\Delta\mathbf{x}, \quad \mathbf{J}^{\dagger} = \mathbf{J}^T(\mathbf{J}\mathbf{J}^T+\lambda^2\mathbf{I})^{-1}",
        ascii="x = J(q)q, = J^, J^ = J^T(JJ^T+lambda^2I)^-1",
        method="Jacobian-based inverse kinematics with damped least squares (DLS). Iteratively solves for joint angles from end-effector pose.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "quintic_polynomial_trajectory": FormulaInfo(
        algorithm="quintic_polynomial_trajectory",
        latex=r"q(t) = a_0+a_1 t+a_2 t^2+a_3 t^3+a_4 t^4+a_5 t^5, \quad \text{with } q(0),\dot{q}(0),\ddot{q}(0),q(T),\dot{q}(T),\ddot{q}(T) \text{ given}",
        ascii="q(t) = a_0+a_1 t+a_2 t^2+a_3 t^3+a_4 t^4+a_5 t^5, with q(0),q(0),q(0),q(T),q(T),q(T) given",
        method="Quintic polynomial trajectory planning. Ensures continuous position, velocity, and acceleration at start/end.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "trapezoidal_velocity_profile": FormulaInfo(
        algorithm="trapezoidal_velocity_profile",
        latex=r"v(t) = \begin{cases} \frac{v_{max}}{t_a}t & 0 \leq t < t_a \\ v_{max} & t_a \leq t < t_a+t_c \\ v_{max}-\frac{v_{max}}{t_d}(t-t_a-t_c) & t_a+t_c \leq t \leq T \end{cases}",
        ascii="v(t) = cases v_maxt_at & 0 t < t_a  v_max & t_a t < t_a+t_c  v_max-v_maxt_d(t-t_a-t_c) & t_a+t_c t T cases",
        method="Trapezoidal velocity profile for motion planning. Three phases: acceleration, constant velocity, deceleration.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "a_star_pathfinding": FormulaInfo(
        algorithm="a_star_pathfinding",
        latex=r"f(n) = g(n) + h(n), \quad g(n) = \text{cost from start to } n, \quad h(n) = \text{heuristic estimate to goal}",
        ascii="f(n) = g(n) + h(n), g(n) = cost from start to n, h(n) = heuristic estimate to goal",
        method="A* pathfinding algorithm. Best-first graph search with admissible heuristic. Optimal and complete.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rrt_rapidly_exploring": FormulaInfo(
        algorithm="rrt_rapidly_exploring",
        latex=r"\mathbf{x}_{new} = \mathbf{x}_{near} + \eta\frac{\mathbf{x}_{rand}-\mathbf{x}_{near}}{\|\mathbf{x}_{rand}-\mathbf{x}_{near}\|}",
        ascii="x_new = x_near + etax_rand-x_near|x_rand-x_near|",
        method="Rapidly-exploring Random Trees (RRT). Sampling-based motion planning for high-dimensional configuration spaces.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "slam_ekf": FormulaInfo(
        algorithm="slam_ekf",
        latex=r"\begin{bmatrix}\hat{\mathbf{x}}_r \\ \hat{\mathbf{m}}\end{bmatrix}_{k+1} = f\left(\begin{bmatrix}\hat{\mathbf{x}}_r \\ \hat{\mathbf{m}}\end{bmatrix}_k, \mathbf{u}_k\right), \quad \mathbf{P} \in \mathbb{R}^{(3+2N)\times(3+2N)}",
        ascii="bmatrixx_r  mbmatrix_k+1 = f (bmatrixx_r  mbmatrix_k, u_k ), P R^(3+2N)x(3+2N)",
        method="EKF-SLAM for simultaneous localization and mapping. Joint state of robot pose and landmark positions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "quaternion_rotation": FormulaInfo(
        algorithm="quaternion_rotation",
        latex=r"\mathbf{p}' = \mathbf{q} \otimes \mathbf{p} \otimes \mathbf{q}^*, \quad \mathbf{q} = \cos\frac{\theta}{2} + \sin\frac{\theta}{2}(u_x\mathbf{i}+u_y\mathbf{j}+u_z\mathbf{k}), \quad \|\mathbf{q}\|=1",
        ascii="p' = q p q^*, q = (theta)/(2) + (theta)/(2)(u_xi+u_yj+u_zk), |q|=1",
        method="Quaternion rotation. Gimbal-lock-free 3D rotation representation. Computationally efficient, numerically stable.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rodrigues_rotation": FormulaInfo(
        algorithm="rodrigues_rotation",
        latex=r"\mathbf{v}' = \mathbf{v}\cos\theta + (\mathbf{k}\times\mathbf{v})\sin\theta + \mathbf{k}(\mathbf{k}\cdot\mathbf{v})(1-\cos\theta)",
        ascii="v' = v + (kxv) + k(k*v)(1-)",
        method="Rodrigues' rotation formula. Rotates vector v by angle theta around unit axis k. Equivalent to matrix exponential on SO(3).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "tsiolkovsky_rocket": FormulaInfo(
        algorithm="tsiolkovsky_rocket",
        latex=r"\Delta v = I_{sp}\,g_0 \ln\frac{m_0}{m_f} = v_e \ln\frac{m_0}{m_f}",
        ascii="v = I_sp g_0 (m_0)/(m_f) = v_e (m_0)/(m_f)",
        method="Tsiolkovsky rocket equation. Relates delta-v to exhaust velocity and mass ratio. Foundation of rocket propulsion.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kepler_orbit": FormulaInfo(
        algorithm="kepler_orbit",
        latex=r"r = \frac{a(1-e^2)}{1+e\cos\nu}, \quad T = 2\pi\sqrt{\frac{a^3}{\mu}}, \quad E - e\sin E = M",
        ascii="r = (a(1-e^2))/(1+e), T = 2pisqrt((a^3)/(mu)), E - e E = M",
        method="Kepler orbital mechanics. Orbit equation, period, and Kepler's equation relating mean and eccentric anomaly.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "vis_viva": FormulaInfo(
        algorithm="vis_viva",
        latex=r"v^2 = \mu\left(\frac{2}{r}-\frac{1}{a}\right)",
        ascii="v^2 = mu ((2)/(r)-(1)/(a) )",
        method="Vis-viva equation. Relates orbital velocity to position and semi-major axis. Derived from energy conservation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "isa_atmosphere": FormulaInfo(
        algorithm="isa_atmosphere",
        latex=r"T = T_0 + L \cdot h, \quad p = p_0\left(\frac{T}{T_0}\right)^{-g_0/(LR)}, \quad \rho = \frac{p}{R_{air}T}",
        ascii="T = T_0 + L * h, p = p_0 ((T)/(T_0) )^-g_0/(LR), rho = (p)/(R_air)T",
        method="International Standard Atmosphere. Temperature, pressure, density as functions of geopotential altitude.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "six_dof_eom": FormulaInfo(
        algorithm="six_dof_eom",
        latex=r"m\dot{\mathbf{V}} = \mathbf{F} - m\boldsymbol{\omega}\times\mathbf{V}, \quad \mathbf{I}\dot{\boldsymbol{\omega}} = \mathbf{M} - \boldsymbol{\omega}\times(\mathbf{I}\boldsymbol{\omega})",
        ascii="mV = F - momegaxV, Iomega = M - omegax(Iomega)",
        method="6-DOF rigid body equations of motion. Newton-Euler formulation in body-fixed frame for flight dynamics.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "drag_coefficient": FormulaInfo(
        algorithm="drag_coefficient",
        latex=r"D = \frac{1}{2}\rho v^2 S C_D, \quad C_D = C_{D0} + \frac{C_L^2}{\pi e AR}",
        ascii="D = (1)/(2)rho v^2 S C_D, C_D = C_D0 + (C_L^2)/(pi e AR)",
        method="Aerodynamic drag model with drag polar. Total drag = parasitic + induced drag. e is Oswald efficiency factor.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hohmann_transfer": FormulaInfo(
        algorithm="hohmann_transfer",
        latex=r"\Delta v_1 = \sqrt{\frac{\mu}{r_1}}\left(\sqrt{\frac{2r_2}{r_1+r_2}}-1\right), \quad \Delta v_2 = \sqrt{\frac{\mu}{r_2}}\left(1-\sqrt{\frac{2r_1}{r_1+r_2}}\right)",
        ascii="v_1 = sqrt((mu)/(r_1)) (sqrt((2r_2)/(r_1+r_2))-1 ), v_2 = sqrt((mu)/(r_2)) (1-sqrt((2r_1)/(r_1+r_2)) )",
        method="Hohmann transfer orbit. Minimum-energy two-impulse transfer between coplanar circular orbits.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "thrust_equation": FormulaInfo(
        algorithm="thrust_equation",
        latex=r"F = \dot{m} v_e + (p_e - p_a) A_e, \quad I_{sp} = \frac{F}{\dot{m}\,g_0}",
        ascii="F = m v_e + (p_e - p_a) A_e, I_sp = (F)/(m) g_0",
        method="Rocket thrust equation. Sum of momentum thrust and pressure thrust at nozzle exit.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "van_der_waals": FormulaInfo(
        algorithm="van_der_waals",
        latex=r"\left(p + \frac{a}{V_m^2}\right)(V_m - b) = RT",
        ascii="(p + (a)/(V_m^2) )(V_m - b) = RT",
        method="van der Waals equation of state. Corrects ideal gas law for intermolecular attractions (a) and molecular volume (b).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "peng_robinson_eos": FormulaInfo(
        algorithm="peng_robinson_eos",
        latex=r"p = \frac{RT}{V_m-b} - \frac{a(T)}{V_m(V_m+b)+b(V_m-b)}, \quad a(T) = 0.45724\frac{R^2 T_c^2}{p_c}\alpha(T_r,\omega)",
        ascii="p = (RT)/(V_m-b) - (a(T))/(V_m(V_m+b)+b(V_m-b)), a(T) = 0.45724(R^2 T_c^2)/(p_c)alpha(T_r,omega)",
        method="Peng-Robinson equation of state. Industry-standard cubic EOS for VLE calculations in process engineering.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "srk_eos": FormulaInfo(
        algorithm="srk_eos",
        latex=r"p = \frac{RT}{V_m-b} - \frac{a(T)}{V_m(V_m+b)}, \quad a(T) = 0.42748\frac{R^2 T_c^2}{p_c}\alpha(T_r,\omega)",
        ascii="p = (RT)/(V_m-b) - (a(T))/(V_m(V_m+b)), a(T) = 0.42748(R^2 T_c^2)/(p_c)alpha(T_r,omega)",
        method="Soave-Redlich-Kwong equation of state. Cubic EOS widely used for hydrocarbon systems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "antoine_equation": FormulaInfo(
        algorithm="antoine_equation",
        latex=r"\log_{10} p^* = A - \frac{B}{C+T}",
        ascii="_10 p^* = A - (B)/(C+T)",
        method="Antoine equation for vapor pressure correlation. Three-parameter fit of saturation pressure vs temperature.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "arrhenius_equation": FormulaInfo(
        algorithm="arrhenius_equation",
        latex=r"k = A\exp\left(-\frac{E_a}{RT}\right)",
        ascii="k = A (-(E_a)/(RT) )",
        method="Arrhenius equation for chemical reaction rate constant. Exponential temperature dependence with activation energy.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cstr_reactor": FormulaInfo(
        algorithm="cstr_reactor",
        latex=r"V = \frac{F_{A0} X_A}{-r_A}, \quad \tau = \frac{V}{v_0} = \frac{C_{A0} X_A}{-r_A}",
        ascii="V = F_A0 X_A-r_A, tau = (V)/(v_0) = C_A0 X_A-r_A",
        method="CSTR (Continuous Stirred-Tank Reactor) design equation. Perfect mixing: uniform concentration throughout.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "pfr_reactor": FormulaInfo(
        algorithm="pfr_reactor",
        latex=r"\frac{dF_A}{dV} = r_A, \quad V = F_{A0}\int_0^{X_A}\frac{dX_A}{-r_A}",
        ascii="(dF_A)/(dV) = r_A, V = F_A0int_0^X_A(dX_A)/(-r_A)",
        method="PFR (Plug Flow Reactor) design equation. No axial mixing, composition varies along reactor length.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ficks_diffusion": FormulaInfo(
        algorithm="ficks_diffusion",
        latex=r"J_A = -D_{AB}\frac{dC_A}{dz}, \quad \frac{\partial C_A}{\partial t} = D_{AB}\nabla^2 C_A",
        ascii="J_A = -D_AB(dC_A)/(dz), (partial C_A)/(partial t) = D_ABnabla^2 C_A",
        method="Fick's laws of diffusion. First law: flux proportional to concentration gradient. Second law: transient diffusion equation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "lmtd_heat_exchanger": FormulaInfo(
        algorithm="lmtd_heat_exchanger",
        latex=r"Q = U A \Delta T_{lm}, \quad \Delta T_{lm} = \frac{\Delta T_1 - \Delta T_2}{\ln(\Delta T_1/\Delta T_2)}",
        ascii="Q = U A T_lm, T_lm = ( T_1 - T_2)/(( T_1/ T_2))",
        method="LMTD method for heat exchanger design. Uses logarithmic mean temperature difference for sizing.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ntu_effectiveness": FormulaInfo(
        algorithm="ntu_effectiveness",
        latex=r"\varepsilon = \frac{Q}{Q_{max}} = f(NTU, C_r), \quad NTU = \frac{UA}{C_{min}}, \quad C_r = \frac{C_{min}}{C_{max}}",
        ascii="= (Q)/(Q_max) = f(NTU, C_r), NTU = (UA)/(C_min), C_r = C_minC_max",
        method="NTU-effectiveness method for heat exchangers. Alternative to LMTD when outlet temperatures are unknown.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "conjugate_gradient_method": FormulaInfo(
        algorithm="conjugate_gradient_method",
        latex=r"\mathbf{x}_{k+1} = \mathbf{x}_k + \alpha_k \mathbf{d}_k, \quad \mathbf{d}_{k+1} = -\nabla f_{k+1}+\beta_k\mathbf{d}_k, \quad \beta_k^{FR} = \frac{\|\nabla f_{k+1}\|^2}{\|\nabla f_k\|^2}",
        ascii="x_k+1 = x_k + alpha_k d_k, d_k+1 = -nabla f_k+1+beta_kd_k, beta_k^FR = |nabla f_k+1|^2|nabla f_k|^2",
        method="Nonlinear conjugate gradient method. Fletcher-Reeves or Polak-Ribiere variants. Effective for large-scale unconstrained optimization.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bfgs_method": FormulaInfo(
        algorithm="bfgs_method",
        latex=r"\mathbf{H}_{k+1} = \left(\mathbf{I}-\frac{\mathbf{s}_k\mathbf{y}_k^T}{\mathbf{y}_k^T\mathbf{s}_k}\right)\mathbf{H}_k\left(\mathbf{I}-\frac{\mathbf{y}_k\mathbf{s}_k^T}{\mathbf{y}_k^T\mathbf{s}_k}\right)+\frac{\mathbf{s}_k\mathbf{s}_k^T}{\mathbf{y}_k^T\mathbf{s}_k}",
        ascii="H_k+1 = (I-s_ky_k^Ty_k^Ts_k )H_k (I-y_ks_k^Ty_k^Ts_k )+s_ks_k^Ty_k^Ts_k",
        method="BFGS quasi-Newton optimization. Rank-2 update of inverse Hessian approximation. Superlinear convergence.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "l_bfgs_method": FormulaInfo(
        algorithm="l_bfgs_method",
        latex=r"\mathbf{d}_k = -\mathbf{H}_k \nabla f_k, \quad \text{two-loop recursion with } m \text{ stored } (\mathbf{s}_i, \mathbf{y}_i) \text{ pairs}",
        ascii="d_k = -H_k nabla f_k, two-loop recursion with m stored (s_i, y_i) pairs",
        method="L-BFGS (Limited-memory BFGS). Stores only m vector pairs instead of full Hessian. Standard for large-scale optimization.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "simulated_annealing_opt": FormulaInfo(
        algorithm="simulated_annealing_opt",
        latex=r"P(\text{accept}) = \begin{cases} 1 & \Delta E \leq 0 \\ e^{-\Delta E / T} & \Delta E > 0 \end{cases}, \quad T_{k+1} = \alpha T_k, \; 0 < \alpha < 1",
        ascii="P(accept) = cases 1 & E 0  e^- E / T & E > 0 cases, T_k+1 = alpha T_k, 0 < alpha < 1",
        method="Simulated annealing for global optimization. Accepts uphill moves with probability decreasing with temperature.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "genetic_algorithm": FormulaInfo(
        algorithm="genetic_algorithm",
        latex=r"\text{Selection} \to \text{Crossover}(p_c) \to \text{Mutation}(p_m) \to \text{Fitness evaluation} \to \text{Elitism}",
        ascii="Selection Crossover(p_c) Mutation(p_m) Fitness evaluation Elitism",
        method="Genetic algorithm for evolutionary optimization. Population-based metaheuristic inspired by natural selection.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "particle_swarm": FormulaInfo(
        algorithm="particle_swarm",
        latex=r"\mathbf{v}_i^{t+1} = w\mathbf{v}_i^t + c_1 r_1(\mathbf{p}_i-\mathbf{x}_i^t)+c_2 r_2(\mathbf{g}-\mathbf{x}_i^t), \quad \mathbf{x}_i^{t+1}=\mathbf{x}_i^t+\mathbf{v}_i^{t+1}",
        ascii="v_i^t+1 = wv_i^t + c_1 r_1(p_i-x_i^t)+c_2 r_2(g-x_i^t), x_i^t+1=x_i^t+v_i^t+1",
        method="Particle Swarm Optimization (PSO). Swarm-based metaheuristic. Particles follow personal and global best positions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sgd_optimizer": FormulaInfo(
        algorithm="sgd_optimizer",
        latex=r"\mathbf{w}_{t+1} = \mathbf{w}_t - \eta \nabla L(\mathbf{w}_t; \mathbf{x}_i, y_i)",
        ascii="w_t+1 = w_t - eta nabla L(w_t; x_i, y_i)",
        method="Stochastic Gradient Descent. Updates parameters using gradient of loss on random mini-batch.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "momentum_optimizer": FormulaInfo(
        algorithm="momentum_optimizer",
        latex=r"\mathbf{v}_{t+1} = \beta\mathbf{v}_t + \nabla L(\mathbf{w}_t), \quad \mathbf{w}_{t+1} = \mathbf{w}_t - \eta\mathbf{v}_{t+1}",
        ascii="v_t+1 = betav_t + nabla L(w_t), w_t+1 = w_t - etav_t+1",
        method="SGD with momentum (Polyak heavy ball). Accumulates past gradients to dampen oscillations and accelerate convergence.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "adagrad_optimizer": FormulaInfo(
        algorithm="adagrad_optimizer",
        latex=r"\mathbf{G}_{t} = \mathbf{G}_{t-1} + (\nabla L_t)^2, \quad \mathbf{w}_{t+1} = \mathbf{w}_t - \frac{\eta}{\sqrt{\mathbf{G}_t + \epsilon}}\nabla L_t",
        ascii="G_t = G_t-1 + (nabla L_t)^2, w_t+1 = w_t - (eta)/(sqrt(G)_t + epsilon)nabla L_t",
        method="AdaGrad optimizer. Adapts learning rate per parameter based on accumulated squared gradients.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rmsprop_optimizer": FormulaInfo(
        algorithm="rmsprop_optimizer",
        latex=r"\mathbf{v}_t = \gamma\mathbf{v}_{t-1} + (1-\gamma)(\nabla L_t)^2, \quad \mathbf{w}_{t+1} = \mathbf{w}_t - \frac{\eta}{\sqrt{\mathbf{v}_t+\epsilon}}\nabla L_t",
        ascii="v_t = gammav_t-1 + (1-gamma)(nabla L_t)^2, w_t+1 = w_t - (eta)/(sqrt(v)_t+epsilon)nabla L_t",
        method="RMSProp optimizer (Hinton). Fixes AdaGrad's diminishing learning rate with exponential moving average of squared gradients.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bayesian_optimization": FormulaInfo(
        algorithm="bayesian_optimization",
        latex=r"\mathbf{x}_{next} = \arg\max_{\mathbf{x}} \alpha(\mathbf{x}|\mathcal{D}), \quad \alpha_{EI}(\mathbf{x}) = \mathbb{E}[\max(f(\mathbf{x})-f^+, 0)]",
        ascii="x_next = _x alpha(x|D), alpha_EI(x) = E[(f(x)-f^+, 0)]",
        method="Bayesian optimization. Uses Gaussian process surrogate and acquisition function (EI, UCB) for black-box optimization.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "trust_region_newton": FormulaInfo(
        algorithm="trust_region_newton",
        latex=r"\min_{\mathbf{p}} m_k(\mathbf{p}) = f_k + \nabla f_k^T \mathbf{p} + \frac{1}{2}\mathbf{p}^T\mathbf{B}_k\mathbf{p} \quad \text{s.t. } \|\mathbf{p}\| \leq \Delta_k",
        ascii="_p m_k(p) = f_k + nabla f_k^T p + (1)/(2)p^TB_kp s.t. |p| _k",
        method="Trust-region Newton-CG method. Minimizes quadratic model within trust radius. Robust for non-convex problems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "admm_optimization": FormulaInfo(
        algorithm="admm_optimization",
        latex=r"\mathbf{x}^{k+1} = \arg\min_{\mathbf{x}} f(\mathbf{x})+\frac{\rho}{2}\|\mathbf{A}\mathbf{x}+\mathbf{B}\mathbf{z}^k-\mathbf{c}+\mathbf{u}^k\|_2^2",
        ascii="x^k+1 = _x f(x)+(rho)/(2)|Ax+Bz^k-c+u^k|_2^2",
        method="ADMM (Alternating Direction Method of Multipliers). Decomposes convex optimization into tractable sub-problems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "runge_kutta_fehlberg": FormulaInfo(
        algorithm="runge_kutta_fehlberg",
        latex=r"\mathbf{y}_{n+1} = \mathbf{y}_n + \sum_{i=1}^{6} b_i \mathbf{k}_i, \quad \hat{\mathbf{y}}_{n+1} = \mathbf{y}_n + \sum_{i=1}^{6} \hat{b}_i \mathbf{k}_i, \quad \text{err} = \|\mathbf{y}_{n+1}-\hat{\mathbf{y}}_{n+1}\|",
        ascii="y_n+1 = y_n + sum_i=1^6 b_i k_i, y_n+1 = y_n + sum_i=1^6 b_i k_i, err = |y_n+1-y_n+1|",
        method="Runge-Kutta-Fehlberg (RKF45). Embedded pair for adaptive step-size control. 4th/5th order error estimation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "adams_bashforth": FormulaInfo(
        algorithm="adams_bashforth",
        latex=r"y_{n+1} = y_n + h\sum_{j=0}^{s-1}b_j f_{n-j}, \quad \text{AB4: } y_{n+1}=y_n+\frac{h}{24}(55f_n-59f_{n-1}+37f_{n-2}-9f_{n-3})",
        ascii="y_n+1 = y_n + hsum_j=0^s-1b_j f_n-j, AB4: y_n+1=y_n+(h)/(24)(55f_n-59f_n-1+37f_n-2-9f_n-3)",
        method="Adams-Bashforth explicit multistep methods. Uses past function evaluations. AB4 is 4th-order with 4 history points.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "adams_moulton": FormulaInfo(
        algorithm="adams_moulton",
        latex=r"y_{n+1} = y_n + h\sum_{j=-1}^{s-1}b_j f_{n-j}, \quad \text{AM3: } y_{n+1}=y_n+\frac{h}{12}(5f_{n+1}+8f_n-f_{n-1})",
        ascii="y_n+1 = y_n + hsum_j=-1^s-1b_j f_n-j, AM3: y_n+1=y_n+(h)/(12)(5f_n+1+8f_n-f_n-1)",
        method="Adams-Moulton implicit multistep methods. Used as corrector in predictor-corrector pairs.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "crank_nicolson": FormulaInfo(
        algorithm="crank_nicolson",
        latex=r"\frac{u^{n+1}-u^n}{\Delta t} = \frac{1}{2}\left[F(u^{n+1})+F(u^n)\right]",
        ascii="u^n+1-u^n t = (1)/(2) [F(u^n+1)+F(u^n) ]",
        method="Crank-Nicolson time integration. Trapezoidal rule, 2nd-order accurate, A-stable. Standard for parabolic PDEs.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "verlet_integration": FormulaInfo(
        algorithm="verlet_integration",
        latex=r"\mathbf{x}(t+\Delta t) = 2\mathbf{x}(t) - \mathbf{x}(t-\Delta t) + \mathbf{a}(t)\Delta t^2, \quad \text{Velocity Verlet: } \mathbf{x}_{n+1}=\mathbf{x}_n+\mathbf{v}_n\Delta t+\frac{1}{2}\mathbf{a}_n\Delta t^2",
        ascii="x(t+ t) = 2x(t) - x(t- t) + a(t) t^2, Velocity Verlet: x_n+1=x_n+v_n t+(1)/(2)a_n t^2",
        method="Verlet/velocity-Verlet integration. Symplectic, time-reversible, excellent energy conservation for Hamiltonian systems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sparse_direct_solver": FormulaInfo(
        algorithm="sparse_direct_solver",
        latex=r"\mathbf{A} = \mathbf{P}^T\mathbf{L}\mathbf{U}\mathbf{Q}, \quad \text{fill-in minimized by reordering}",
        ascii="A = P^TLUQ, fill-in minimized by reordering",
        method="Sparse direct solver (supernodal/multifrontal). Uses fill-reducing reordering (AMD/METIS) for efficiency.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "multigrid_method": FormulaInfo(
        algorithm="multigrid_method",
        latex=r"\text{Pre-smooth} \to \text{Restrict residual} \to \text{Coarse solve} \to \text{Prolongate} \to \text{Post-smooth}",
        ascii="Pre-smooth Restrict residual Coarse solve Prolongate Post-smooth",
        method="Multigrid method (geometric/algebraic). O(N) solver using hierarchy of grids. V-cycle and W-cycle variants.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gmres_solver": FormulaInfo(
        algorithm="gmres_solver",
        latex=r"\mathbf{x}_m = \mathbf{x}_0 + \mathbf{V}_m \mathbf{y}_m, \quad \mathbf{y}_m = \arg\min_{\mathbf{y}}\|\beta\mathbf{e}_1 - \mathbf{\bar{H}}_m\mathbf{y}\|_2",
        ascii="x_m = x_0 + V_m y_m, y_m = _y|betae_1 - H_my|_2",
        method="GMRES (Generalized Minimal Residual). Krylov subspace method for nonsymmetric linear systems. Uses Arnoldi process.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "bicgstab_solver": FormulaInfo(
        algorithm="bicgstab_solver",
        latex=r"\mathbf{p}_i = \mathbf{r}_i + \beta_i(\mathbf{p}_{i-1}-\omega_{i-1}\mathbf{A}\mathbf{p}_{i-1}), \quad \alpha_i = \frac{\langle\hat{\mathbf{r}}_0,\mathbf{r}_i\rangle}{\langle\hat{\mathbf{r}}_0,\mathbf{A}\mathbf{p}_i\rangle}",
        ascii="p_i = r_i + beta_i(p_i-1-omega_i-1Ap_i-1), alpha_i = r_0,r_ir_0,Ap_i",
        method="BiCGSTAB (Bi-Conjugate Gradient Stabilized). Krylov solver for nonsymmetric systems, smoother convergence than BiCG.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "incomplete_lu": FormulaInfo(
        algorithm="incomplete_lu",
        latex=r"\mathbf{A} \approx \mathbf{L}\mathbf{U}, \quad l_{ij}=0 \text{ if } a_{ij}=0 \text{ (ILU(0))}, \quad \text{Fill level } p: \text{ILU}(p)",
        ascii="A LU, l_ij=0 if a_ij=0 (ILU(0)), Fill level p: ILU(p)",
        method="Incomplete LU factorization. Sparse preconditioner that drops fill-in entries. ILU(0) preserves sparsity pattern.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "svd_decomposition": FormulaInfo(
        algorithm="svd_decomposition",
        latex=r"\mathbf{A} = \mathbf{U}\boldsymbol{\Sigma}\mathbf{V}^T, \quad \sigma_1 \geq \sigma_2 \geq \cdots \geq \sigma_r > 0",
        ascii="A = U^T, sigma_1 sigma_2 *s sigma_r > 0",
        method="Singular Value Decomposition. Fundamental factorization for rank analysis, least squares, PCA, and compression.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rayleigh_quotient": FormulaInfo(
        algorithm="rayleigh_quotient",
        latex=r"R(\mathbf{x}) = \frac{\mathbf{x}^T\mathbf{A}\mathbf{x}}{\mathbf{x}^T\mathbf{x}}, \quad \lambda_{min} \leq R(\mathbf{x}) \leq \lambda_{max}",
        ascii="R(x) = x^TAxx^Tx, lambda_min R(x) lambda_max",
        method="Rayleigh quotient for eigenvalue estimation. Provides best eigenvalue estimate for given eigenvector approximation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gauss_elimination": FormulaInfo(
        algorithm="gauss_elimination",
        latex=r"a_{ij}^{(k+1)} = a_{ij}^{(k)} - \frac{a_{ik}^{(k)}}{a_{kk}^{(k)}} a_{kj}^{(k)}, \quad \text{with partial pivoting}",
        ascii="a_ij^(k+1) = a_ij^(k) - a_ik^(k)a_kk^(k) a_kj^(k), with partial pivoting",
        method="Gaussian elimination with partial pivoting. Direct method for linear systems. O(n^3) complexity.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "nusselt_correlation": FormulaInfo(
        algorithm="nusselt_correlation",
        latex=r"Nu = C \, Re^m Pr^n, \quad Nu = \frac{hL}{k}, \quad Re = \frac{\rho u L}{\mu}, \quad Pr = \frac{\mu c_p}{k}",
        ascii="Nu = C Re^m Pr^n, Nu = (hL)/(k), Re = (rho u L)/(mu), Pr = (mu c_p)/(k)",
        method="Nusselt number correlations for convective heat transfer. Dittus-Boelter for turbulent internal flow.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rayleigh_benard": FormulaInfo(
        algorithm="rayleigh_benard",
        latex=r"Ra = \frac{g\beta(T_h-T_c)L^3}{\nu\alpha}, \quad Ra_c = 1708 \text{ (onset of convection)}",
        ascii="Ra = (gbeta(T_h-T_c)L^3)/(nualpha), Ra_c = 1708 (onset of convection)",
        method="Rayleigh-Benard convection. Ra number determines onset and nature of buoyancy-driven convection.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "finite_volume_method": FormulaInfo(
        algorithm="finite_volume_method",
        latex=r"\frac{d}{dt}\int_{\Omega}\phi\,dV + \oint_{\partial\Omega}\phi\mathbf{u}\cdot\mathbf{n}\,dA = \oint_{\partial\Omega}\Gamma\nabla\phi\cdot\mathbf{n}\,dA + \int_{\Omega}S\,dV",
        ascii="(d)/(dt)int_phi dV + _partialphiu*n dA = _partial*n dA + int_S dV",
        method="Finite Volume Method. Integral conservation over control volumes. Naturally conservative, standard in CFD.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "boundary_element_method": FormulaInfo(
        algorithm="boundary_element_method",
        latex=r"c(\mathbf{x})u(\mathbf{x}) + \int_{\Gamma}q^*(\mathbf{x},\mathbf{y})u(\mathbf{y})\,d\Gamma = \int_{\Gamma}u^*(\mathbf{x},\mathbf{y})q(\mathbf{y})\,d\Gamma",
        ascii="c(x)u(x) + int_q^*(x,y)u(y) d = int_u^*(x,y)q(y) d",
        method="Boundary Element Method. Reduces domain problem to boundary integral. Uses fundamental solution (Green's function).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "spectral_method": FormulaInfo(
        algorithm="spectral_method",
        latex=r"u_N(x) = \sum_{k=0}^{N}\hat{u}_k \phi_k(x), \quad \text{Galerkin: } \langle R_N, \phi_j \rangle = 0, \; j=0,...,N",
        ascii="u_N(x) = sum_k=0^Nu_k phi_k(x), Galerkin: R_N, phi_j = 0, j=0,...,N",
        method="Spectral methods. Expand solution in global basis (Fourier, Chebyshev, Legendre). Exponential convergence for smooth problems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "isogeometric_analysis": FormulaInfo(
        algorithm="isogeometric_analysis",
        latex=r"\mathbf{u}^h(\boldsymbol{\xi}) = \sum_{A=1}^{n} R_{A,p}(\boldsymbol{\xi})\mathbf{d}_A, \quad R_{A,p} = \text{NURBS basis functions}",
        ascii="u^h(xi) = sum_A=1^n R_A,p(xi)d_A, R_A,p = NURBS basis functions",
        method="Isogeometric Analysis (IGA). Uses NURBS basis from CAD geometry directly as FE shape functions. Exact geometry.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sparse_matrix_csr": FormulaInfo(
        algorithm="sparse_matrix_csr",
        latex=r"\text{CSR: } (\mathbf{val}, \mathbf{col\_idx}, \mathbf{row\_ptr}), \quad \text{Memory: } O(nnz + n)",
        ascii="CSR: (val, col_idx, row_ptr), Memory: O(nnz + n)",
        method="Compressed Sparse Row (CSR) format. Standard sparse matrix storage. O(nnz) memory, efficient row-slice and SpMV.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "monte_carlo_integration": FormulaInfo(
        algorithm="monte_carlo_integration",
        latex=r"I = \int_\Omega f(\mathbf{x})\,d\mathbf{x} \approx \frac{V}{N}\sum_{i=1}^{N}f(\mathbf{x}_i), \quad \sigma_I = \frac{V}{\sqrt{N}}\sigma_f",
        ascii="I = int_ f(x) dx (V)/(N)sum_i=1^Nf(x_i), sigma_I = (V)/(sqrt(N))sigma_f",
        method="Monte Carlo integration. Convergence rate O(1/sqrt(N)) independent of dimension. Ideal for high-dimensional integrals.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "hermite_interpolation": FormulaInfo(
        algorithm="hermite_interpolation",
        latex=r"H_{2n+1}(x) = \sum_{i=0}^{n}f(x_i)H_i(x) + \sum_{i=0}^{n}f'(x_i)\hat{H}_i(x)",
        ascii="H_2n+1(x) = sum_i=0^nf(x_i)H_i(x) + sum_i=0^nf'(x_i)H_i(x)",
        method="Hermite interpolation. Matches both function values and derivatives at nodes. Cubic Hermite uses 4 data points.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "richardson_extrapolation": FormulaInfo(
        algorithm="richardson_extrapolation",
        latex=r"I = I(h) + c_p h^p + c_{p+1}h^{p+1} + \cdots, \quad I^* = \frac{2^p I(h/2)-I(h)}{2^p-1}",
        ascii="I = I(h) + c_p h^p + c_p+1h^p+1 + *s, I^* = (2^p I(h/2)-I(h))/(2^p-1)",
        method="Richardson extrapolation. Improves accuracy by combining results at different step sizes. Basis for Romberg integration.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "elastic_wave_equation": FormulaInfo(
        algorithm="elastic_wave_equation",
        latex=r"\rho \ddot{\mathbf{u}} = \nabla \cdot \boldsymbol{\sigma} + \mathbf{f}, \quad c_p = \sqrt{\frac{\lambda+2\mu}{\rho}}, \quad c_s = \sqrt{\frac{\mu}{\rho}}",
        ascii="rho u = nabla * sigma + f, c_p = sqrt((lambda+2mu)/(rho)), c_s = sqrt((mu)/(rho))",
        method="Elastic wave equation. P-wave (compressional) and S-wave (shear) propagation in solids. Basis for seismology and NDE.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rayleigh_damping": FormulaInfo(
        algorithm="rayleigh_damping",
        latex=r"\mathbf{C} = \alpha_M \mathbf{M} + \beta_K \mathbf{K}, \quad \zeta_i = \frac{\alpha_M}{2\omega_i}+\frac{\beta_K \omega_i}{2}",
        ascii="C = alpha_M M + beta_K K, zeta_i = (alpha_M)/(2omega_i)+(beta_K omega_i)/(2)",
        method="Rayleigh (proportional) damping. Damping matrix as linear combination of mass and stiffness matrices.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "wilson_theta": FormulaInfo(
        algorithm="wilson_theta",
        latex=r"\mathbf{M}\ddot{\mathbf{u}}_{n+\theta} + \mathbf{C}\dot{\mathbf{u}}_{n+\theta}+\mathbf{K}\mathbf{u}_{n+\theta} = \mathbf{F}_{n+\theta}, \quad \theta \geq 1.37",
        ascii="Mu_n+theta + Cu_n+theta+Ku_n+theta = F_n+theta, theta 1.37",
        method="Wilson-theta method for structural dynamics. Unconditionally stable for theta >= 1.37. Extended Newmark variant.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "stress_intensity_factor": FormulaInfo(
        algorithm="stress_intensity_factor",
        latex=r"K_I = \sigma\sqrt{\pi a}\,Y(a/W), \quad G = \frac{K_I^2}{E'}, \quad E' = \begin{cases}E & \text{plane stress}\\E/(1-\nu^2) & \text{plane strain}\end{cases}",
        ascii="K_I = sigmasqrt(pi a) Y(a/W), G = (K_I^2)/(E'), E' = casesE & plane stress/(1-nu^2) & plane straincases",
        method="Stress intensity factor and energy release rate. K_I characterizes crack-tip stress field. G = K^2/E' (Irwin relation).",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "j_integral": FormulaInfo(
        algorithm="j_integral",
        latex=r"J = \oint_{\Gamma}\left(W\,dy - \mathbf{T}\cdot\frac{\partial\mathbf{u}}{\partial x}\,ds\right), \quad J = G \text{ (for linear elastic)}",
        ascii="J = _ (W dy - T*partialupartial x ds ), J = G (for linear elastic)",
        method="J-integral (Rice 1968). Path-independent contour integral for fracture. Equals G for linear elastic, extends to plasticity.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "paris_law": FormulaInfo(
        algorithm="paris_law",
        latex=r"\frac{da}{dN} = C(\Delta K)^m, \quad \Delta K = K_{max}-K_{min}",
        ascii="(da)/(dN) = C( K)^m, K = K_max-K_min",
        method="Paris fatigue crack growth law. Power-law relation between crack growth rate and stress intensity factor range.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "navier_stokes_compressible": FormulaInfo(
        algorithm="navier_stokes_compressible",
        latex=r"\frac{\partial \rho}{\partial t}+\nabla\cdot(\rho\mathbf{u})=0, \quad \frac{\partial(\rho\mathbf{u})}{\partial t}+\nabla\cdot(\rho\mathbf{u}\otimes\mathbf{u}+p\mathbf{I})=\nabla\cdot\boldsymbol{\tau}",
        ascii="(partial rho)/(partial t)+nabla*(rhou)=0, partial(rhou)partial t+nabla*(rhou+pI)=nabla*tau",
        method="Compressible Navier-Stokes equations in conservation form. Full system with energy equation for high-Mach flows.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "turbulence_wall_function": FormulaInfo(
        algorithm="turbulence_wall_function",
        latex=r"u^+ = \begin{cases}y^+ & y^+ < 11.06 \\ \frac{1}{\kappa}\ln(y^+)+B & y^+ > 11.06\end{cases}, \quad y^+ = \frac{y u_\tau}{\nu}, \quad u^+=\frac{u}{u_\tau}",
        ascii="u^+ = casesy^+ & y^+ < 11.06  (1)/(kappa)(y^+)+B & y^+ > 11.06cases, y^+ = (y u_tau)/(nu), u^+=(u)/(u_tau)",
        method="Turbulent wall functions (law of the wall). Bridges viscous sublayer to log-law region. Avoids resolving boundary layer.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "dynamic_smagorinsky": FormulaInfo(
        algorithm="dynamic_smagorinsky",
        latex=r"C_s^2 = \frac{\langle L_{ij}M_{ij}\rangle}{\langle M_{ij}M_{ij}\rangle}, \quad L_{ij} = \widehat{\bar{u}_i\bar{u}_j}-\hat{\bar{u}}_i\hat{\bar{u}}_j",
        ascii="C_s^2 = L_ijM_ij M_ijM_ij, L_ij = u_iu_j-u_iu_j",
        method="Dynamic Smagorinsky model (Germano 1991). Computes Cs dynamically from resolved scales using test filter.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "sa_ddes": FormulaInfo(
        algorithm="sa_ddes",
        latex=r"\tilde{d} = d - f_d \max(0, d - C_{DES}\Delta), \quad f_d = 1 - \tanh\left[(8r_d)^3\right]",
        ascii="d = d - f_d (0, d - C_DES), f_d = 1 - [(8r_d)^3 ]",
        method="Delayed Detached Eddy Simulation (DDES). Adds shielding function fd to prevent grid-induced separation in boundary layers.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "ale_formulation": FormulaInfo(
        algorithm="ale_formulation",
        latex=r"\left.\frac{\partial \phi}{\partial t}\right|_{\chi} + (\mathbf{u}-\hat{\mathbf{u}})\cdot\nabla\phi = \text{RHS}, \quad \hat{\mathbf{u}} = \text{mesh velocity}",
        ascii=".(partial phi)/(partial t) |_chi + (u-u)*nablaphi = RHS, u = mesh velocity",
        method="Arbitrary Lagrangian-Eulerian formulation. Moving mesh framework for FSI and free-surface problems.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cfl_condition": FormulaInfo(
        algorithm="cfl_condition",
        latex=r"CFL = \frac{(|u|+c)\Delta t}{\Delta x} \leq CFL_{max}, \quad \Delta t \leq CFL_{max} \frac{\Delta x}{|u|+c}",
        ascii="CFL = ((|u|+c) t)/( x) CFL_max, t CFL_max ( x)/(|u|+c)",
        method="Courant-Friedrichs-Lewy condition. Necessary stability condition for explicit time-stepping schemes.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "tvd_limiter": FormulaInfo(
        algorithm="tvd_limiter",
        latex=r"\phi(r) = \max(0, \min(2r,1), \min(r,2)) \quad \text{(superbee)}, \quad r = \frac{\Delta u_{i-1/2}}{\Delta u_{i+1/2}}",
        ascii="phi(r) = (0, (2r,1), (r,2)) (superbee), r = u_i-1/2 u_i+1/2",
        method="TVD (Total Variation Diminishing) flux limiters. Prevent oscillations near discontinuities while maintaining accuracy.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gauss_jordan_elimination": FormulaInfo(
        algorithm="gauss_jordan_elimination",
        latex=r"[\mathbf{A}|\mathbf{I}] \to [\mathbf{I}|\mathbf{A}^{-1}]",
        ascii="[A|I] [I|A^-1]",
        method="Gauss-Jordan elimination for matrix inversion. Augments A with identity and row-reduces to RREF.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "cholesky_ldl": FormulaInfo(
        algorithm="cholesky_ldl",
        latex=r"\mathbf{A} = \mathbf{L}\mathbf{D}\mathbf{L}^T, \quad d_{ii} = a_{ii} - \sum_{k=1}^{i-1}l_{ik}^2 d_{kk}",
        ascii="A = LDL^T, d_ii = a_ii - sum_k=1^i-1l_ik^2 d_kk",
        method="LDL^T factorization. Cholesky variant without square roots. Works for symmetric indefinite with pivoting.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "eigenvalue_qr_shift": FormulaInfo(
        algorithm="eigenvalue_qr_shift",
        latex=r"\mathbf{A}_k - \mu_k \mathbf{I} = \mathbf{Q}_k\mathbf{R}_k, \quad \mathbf{A}_{k+1} = \mathbf{R}_k\mathbf{Q}_k + \mu_k\mathbf{I}",
        ascii="A_k - mu_k I = Q_kR_k, A_k+1 = R_kQ_k + mu_kI",
        method="QR algorithm with shifts for eigenvalue computation. Wilkinson shift for cubic convergence. Standard for dense matrices.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "inverse_distance_weighting": FormulaInfo(
        algorithm="inverse_distance_weighting",
        latex=r"f(\mathbf{x}) = \frac{\sum_{i=1}^{N} w_i(\mathbf{x}) f_i}{\sum_{i=1}^{N}w_i(\mathbf{x})}, \quad w_i(\mathbf{x}) = \frac{1}{d(\mathbf{x},\mathbf{x}_i)^p}",
        ascii="f(x) = sum_i=1^N w_i(x) f_isum_i=1^Nw_i(x), w_i(x) = (1)/(d(x),x_i)^p",
        method="Inverse Distance Weighting (Shepard's method). Spatial interpolation weighted by inverse distance power p.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "kriging_interpolation": FormulaInfo(
        algorithm="kriging_interpolation",
        latex=r"\hat{Z}(\mathbf{x}_0) = \sum_{i=1}^{n}\lambda_i Z(\mathbf{x}_i), \quad \min \text{Var}[\hat{Z}-Z] \text{ s.t. } \sum\lambda_i=1",
        ascii="Z(x_0) = sum_i=1^nlambda_i Z(x_i), Var[Z-Z] s.t. sumlambda_i=1",
        method="Kriging (Gaussian process regression). Best Linear Unbiased Predictor (BLUP) for spatial interpolation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "radial_basis_function": FormulaInfo(
        algorithm="radial_basis_function",
        latex=r"f(\mathbf{x}) = \sum_{i=1}^{N}w_i \phi(\|\mathbf{x}-\mathbf{x}_i\|), \quad \text{e.g., } \phi(r)=e^{-(\epsilon r)^2}",
        ascii="f(x) = sum_i=1^Nw_i phi(|x-x_i|), e.g., phi(r)=e^-(epsilon r)^2",
        method="Radial Basis Function interpolation. Meshfree method using distance-based basis functions.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "galerkin_weak_form": FormulaInfo(
        algorithm="galerkin_weak_form",
        latex=r"\int_\Omega \boldsymbol{\varepsilon}^T(\delta\mathbf{u}) \boldsymbol{\sigma}\,d\Omega = \int_\Omega \delta\mathbf{u}^T \mathbf{b}\,d\Omega + \int_{\Gamma_t}\delta\mathbf{u}^T \mathbf{t}\,d\Gamma",
        ascii="int_ ^T(deltau) sigma d = int_ deltau^T b d + int__tdeltau^T t d",
        method="Galerkin weak form (principle of virtual work). Foundation of FEM -- weighted residual with test functions from same space.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mass_lumping": FormulaInfo(
        algorithm="mass_lumping",
        latex=r"M_{ii}^{lump} = \rho \int_\Omega N_i\,d\Omega \cdot \frac{\sum_j M_{ij}^{cons}}{\sum_j M_{ij}^{cons}} = \rho \int_\Omega N_i\,d\Omega",
        ascii="M_ii^lump = rho int_ N_i d * sum_j M_ij^conssum_j M_ij^cons = rho int_ N_i d",
        method="Mass lumping (diagonalization). Creates diagonal mass matrix for efficient explicit time integration.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "mach_number_relations": FormulaInfo(
        algorithm="mach_number_relations",
        latex=r"Ma = \frac{v}{a}, \quad \frac{T_0}{T}=1+\frac{\gamma-1}{2}Ma^2, \quad \frac{p_0}{p}=\left(1+\frac{\gamma-1}{2}Ma^2\right)^{\gamma/(\gamma-1)}",
        ascii="Ma = (v)/(a), (T_0)/(T)=1+(gamma-1)/(2)Ma^2, (p_0)/(p)= (1+(gamma-1)/(2)Ma^2 )^gamma/(gamma-1)",
        method="Isentropic flow relations. Stagnation-to-static ratios as functions of Mach number for compressible flow.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "normal_shock_relations": FormulaInfo(
        algorithm="normal_shock_relations",
        latex=r"Ma_2^2 = \frac{Ma_1^2+(2/(\gamma-1))}{(2\gamma/(\gamma-1))Ma_1^2-1}, \quad \frac{p_2}{p_1}=\frac{2\gamma Ma_1^2-(\gamma-1)}{\gamma+1}",
        ascii="Ma_2^2 = (Ma_1^2+(2/(gamma-1)))/((2gamma/(gamma-1))Ma_1^2-1), (p_2)/(p_1)=(2gamma Ma_1^2-(gamma-1))/(gamma+1)",
        method="Normal shock relations (Rankine-Hugoniot). Post-shock Mach, pressure, temperature, density ratios from pre-shock Mach.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "prandtl_meyer_expansion": FormulaInfo(
        algorithm="prandtl_meyer_expansion",
        latex=r"\nu(Ma) = \sqrt{\frac{\gamma+1}{\gamma-1}}\arctan\sqrt{\frac{\gamma-1}{\gamma+1}(Ma^2-1)} - \arctan\sqrt{Ma^2-1}",
        ascii="nu(Ma) = sqrt((gamma+1)/(gamma-1))((gamma-1)/(gamma+1)(Ma^2-1)) - (Ma^2-1)",
        method="Prandtl-Meyer expansion function. Relates Mach number to turning angle in supersonic isentropic expansion.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "thin_airfoil_theory": FormulaInfo(
        algorithm="thin_airfoil_theory",
        latex=r"C_L = 2\pi\alpha, \quad C_{m,LE} = -\frac{C_L}{4}, \quad x_{cp} = \frac{c}{4}",
        ascii="C_L = 2pialpha, C_m,LE = -(C_L)/(4), x_cp = (c)/(4)",
        method="Thin airfoil theory. CL = 2*pi*alpha for symmetric airfoil. Aerodynamic center at quarter chord.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "panel_method": FormulaInfo(
        algorithm="panel_method",
        latex=r"\phi(\mathbf{x}) = \phi_\infty + \sum_{j=1}^{N}\int_{panel_j}\left[\sigma_j G(\mathbf{x},\mathbf{y}) + \mu_j \frac{\partial G}{\partial n_y}\right]dS_j",
        ascii="phi(x) = phi_infty + sum_j=1^Nint_panel_j [sigma_j G(x,y) + mu_j (partial G)/(partial n_y) ]dS_j",
        method="Panel method for potential flow. Distributes sources/doublets on body surface panels. Hess-Smith formulation.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "vortex_lattice_method": FormulaInfo(
        algorithm="vortex_lattice_method",
        latex=r"\mathbf{v}_{ind} = \frac{\Gamma}{4\pi}\frac{(r_1+r_2)(\mathbf{r}_1\times\mathbf{r}_2)}{r_1 r_2(r_1 r_2+\mathbf{r}_1\cdot\mathbf{r}_2)}, \quad \sum_j a_{ij}\Gamma_j = -\mathbf{V}_\infty\cdot\hat{n}_i",
        ascii="v_ind = ()/(4pi)(r_1+r_2)(r_1xr_2)r_1 r_2(r_1 r_2+r_1*r_2), sum_j a_ij_j = -V_infty*n_i",
        method="Vortex Lattice Method. Models lifting surfaces with horseshoe vortices. Fast aerodynamic analysis for wings.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "gurson_tvergaard_needleman": FormulaInfo(
        algorithm="gurson_tvergaard_needleman",
        latex=r"\Phi = \left(\frac{q}{\sigma_y}\right)^2 + 2f^* q_1 \cosh\left(\frac{3q_2 p}{2\sigma_y}\right) - (1+q_3 f^{*2}) = 0",
        ascii="= ((q)/(sigma_y) )^2 + 2f^* q_1 ((3q_2 p)/(2sigma_y) ) - (1+q_3 f^*2) = 0",
        method="Gurson-Tvergaard-Needleman (GTN) damage model. Pressure-dependent yield with void volume fraction for ductile fracture.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "johnson_cook_plasticity": FormulaInfo(
        algorithm="johnson_cook_plasticity",
        latex=r"\sigma_y = (A+B\bar{\varepsilon}^{p\,n})(1+C\ln\dot{\varepsilon}^*)(1-T^{*m})",
        ascii="sigma_y = (A+B^p n)(1+C^*)(1-T^*m)",
        method="Johnson-Cook plasticity model. Empirical model for strain hardening, strain rate, and temperature effects. Used for impact/crash.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "rankine_hugoniot": FormulaInfo(
        algorithm="rankine_hugoniot",
        latex=r"\rho_1 u_1 = \rho_2 u_2, \quad p_1+\rho_1 u_1^2 = p_2+\rho_2 u_2^2, \quad h_1+\frac{u_1^2}{2}=h_2+\frac{u_2^2}{2}",
        ascii="rho_1 u_1 = rho_2 u_2, p_1+rho_1 u_1^2 = p_2+rho_2 u_2^2, h_1+(u_1^2)/(2)=h_2+(u_2^2)/(2)",
        method="Rankine-Hugoniot jump conditions across a shock wave. Conservation of mass, momentum, energy across discontinuity.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

    "spalding_law": FormulaInfo(
        algorithm="spalding_law",
        latex=r"y^+ = u^+ + e^{-\kappa B}\left[e^{\kappa u^+}-1-\kappa u^+-\frac{(\kappa u^+)^2}{2}-\frac{(\kappa u^+)^3}{6}\right]",
        ascii="y^+ = u^+ + e^-kappa B [e^kappa u^+-1-kappa u^+-((kappa u^+)^2)/(2)-((kappa u^+)^3)/(6) ]",
        method="Spalding's single-formula wall law. Continuous composite profile covering viscous sublayer through log layer.",
        reference="Auto-generated from algorithm database v1.2.2",
    ),

}


# -----------------------------------------------------------------------
# Algorithm name normalization
# -----------------------------------------------------------------------

# Tespit edilen AlgorithmMatch.name degerlerini FORMULA_TEMPLATES anahtarlarina
# eslestirmek icin normalizasyon tablosu.  Buyuk/kucuk harf farksiz.
# Birden fazla tespit ismi ayni sablona isaret edebilir.

_NAME_TO_TEMPLATE: dict[str, str] = {}


def _build_name_map() -> None:
    """Build the normalized name -> template key mapping."""
    # Direct exact matches (lowercase)
    for key, info in FORMULA_TEMPLATES.items():
        algo_lower = info.algorithm.lower()
        _NAME_TO_TEMPLATE[algo_lower] = key

    # Additional aliases
    _aliases: dict[str, str] = {
        # Gauss quadrature variants
        "gauss quadrature 1-point": "gauss_quadrature_1pt",
        "gauss quadrature 1pt": "gauss_quadrature_1pt",
        "gauss-legendre 1pt": "gauss_quadrature_1pt",
        "gauss quadrature 2-point": "gauss_quadrature_2pt",
        "gauss quadrature 2pt": "gauss_quadrature_2pt",
        "gauss-legendre 2pt": "gauss_quadrature_2pt",
        "gauss quadrature 3-point": "gauss_quadrature_3pt",
        "gauss quadrature 3pt": "gauss_quadrature_3pt",
        "gauss-legendre 3pt": "gauss_quadrature_3pt",
        "gauss 2x2": "gauss_quadrature_2x2",
        "gauss quadrature 2x2": "gauss_quadrature_2x2",
        "gauss 2x2x2": "gauss_quadrature_2x2x2",
        "gauss quadrature 2x2x2": "gauss_quadrature_2x2x2",
        "gauss 3x3x3": "gauss_quadrature_3x3x3",
        "gauss quadrature 3x3x3": "gauss_quadrature_3x3x3",
        # Newton-Raphson
        "newton-raphson": "newton_raphson",
        "newton raphson": "newton_raphson",
        "newton's method": "newton_raphson",
        # Solvers
        "conjugate gradient": "conjugate_gradient",
        "cg solver": "conjugate_gradient",
        "cg method": "conjugate_gradient",
        "gmres solver": "gmres",
        "gmres method": "gmres",
        "bicgstab solver": "bicgstab",
        "bicgstab method": "bicgstab",
        "preconditioned cg": "preconditioned_cg",
        "pcg": "preconditioned_cg",
        # Direct solvers
        "lu factorization": "lu_decomposition",
        "lu decomposition": "lu_decomposition",
        "lu solve": "lu_decomposition",
        "cholesky factorization": "cholesky",
        "cholesky decomposition": "cholesky",
        # Eigenvalue
        "qr algorithm": "qr_eigenvalue",
        "qr eigenvalue": "qr_eigenvalue",
        "qr iteration": "qr_eigenvalue",
        "power iteration": "power_iteration",
        "power method": "power_iteration",
        # Time integration
        "newmark-beta": "newmark_beta",
        "newmark beta": "newmark_beta",
        "newmark method": "newmark_beta",
        "hht-alpha": "hht_alpha",
        "hht alpha": "hht_alpha",
        "hilber-hughes-taylor": "hht_alpha",
        "runge-kutta 4": "runge_kutta_4",
        "runge-kutta": "runge_kutta_4",
        "rk4": "runge_kutta_4",
        "runge kutta 4th order": "runge_kutta_4",
        # Turbulence
        "k-epsilon": "k_epsilon",
        "k-epsilon turbulence": "k_epsilon",
        "k-epsilon model": "k_epsilon",
        "standard k-epsilon": "k_epsilon",
        "k-omega sst": "k_omega_sst",
        "k-omega sst turbulence": "k_omega_sst",
        "menter sst": "k_omega_sst",
        "sst model": "k_omega_sst",
        # Finance
        "black-scholes": "black_scholes",
        "black scholes": "black_scholes",
        "black-scholes-merton": "black_scholes",
        "bsm": "black_scholes",
        "monte carlo": "monte_carlo_sim",
        "monte carlo simulation": "monte_carlo_sim",
        "mc simulation": "monte_carlo_sim",
        "greeks": "greeks_finite_diff",
        "option greeks": "greeks_finite_diff",
        "finite difference greeks": "greeks_finite_diff",
        "gbm": "geometric_brownian_motion",
        "geometric brownian motion": "geometric_brownian_motion",
        "var": "value_at_risk",
        "value at risk": "value_at_risk",
        # ML
        "gradient descent": "gradient_descent",
        "vanilla gradient descent": "gradient_descent",
        "gd": "gradient_descent",
        "adam": "adam_optimizer",
        "adam optimizer": "adam_optimizer",
        "sgd": "sgd_momentum",
        "sgd with momentum": "sgd_momentum",
        "stochastic gradient descent": "sgd_momentum",
        "softmax activation": "softmax",
        "softmax function": "softmax",
        "relu activation": "relu",
        "sigmoid activation": "sigmoid",
        "logistic function": "sigmoid",
        "batch norm": "batch_normalization",
        "batchnorm": "batch_normalization",
        "cross entropy": "cross_entropy_loss",
        "cross-entropy loss": "cross_entropy_loss",
        "ce loss": "cross_entropy_loss",
        "leaky relu": "leaky_relu",
        "lrelu": "leaky_relu",
        "tanh": "tanh_activation",
        "tanh activation": "tanh_activation",
        "gelu": "gelu_activation",
        "gelu activation": "gelu_activation",
        "layer norm": "layer_normalization",
        "layernorm": "layer_normalization",
        "attention": "attention_mechanism",
        "scaled dot-product attention": "attention_mechanism",
        "self-attention": "attention_mechanism",
        # DSP
        "fft": "fft",
        "fast fourier transform": "fft",
        "cooley-tukey": "fft",
        "dft": "fft",
        "convolution": "convolution_1d",
        "1d convolution": "convolution_1d",
        "fir filter": "fir_filter",
        "fir": "fir_filter",
        "iir filter": "iir_filter",
        "iir": "iir_filter",
        "butterworth": "butterworth_filter",
        "butterworth filter": "butterworth_filter",
        "hamming": "hamming_window",
        "hamming window": "hamming_window",
        "hanning": "hanning_window",
        "hanning window": "hanning_window",
        "hann window": "hanning_window",
        "von hann": "hanning_window",
        "blackman": "blackman_window",
        "blackman window": "blackman_window",
        # Linear algebra
        "svd": "svd",
        "singular value decomposition": "svd",
        "sparse cg": "sparse_cg_solve",
        "sparse cg solve": "sparse_cg_solve",
        "sparse conjugate gradient": "sparse_cg_solve",
        # FEA
        "galerkin": "galerkin_fem",
        "galerkin fem": "galerkin_fem",
        "galerkin method": "galerkin_fem",
        "weak form": "galerkin_fem",
        "isoparametric": "isoparametric_mapping",
        "isoparametric mapping": "isoparametric_mapping",
        "isoparametric element": "isoparametric_mapping",
        "von mises": "von_mises_stress",
        "von mises stress": "von_mises_stress",
        "mises stress": "von_mises_stress",
        # CFD
        "upwind": "upwind_scheme",
        "upwind scheme": "upwind_scheme",
        "first order upwind": "upwind_scheme",
        "central difference": "central_difference",
        "central difference scheme": "central_difference",
        # --- NEW: FEA Core ---
        "stiffness matrix": "stiffness_matrix_assembly",
        "stiffness matrix assembly": "stiffness_matrix_assembly",
        "k matrix": "stiffness_matrix_assembly",
        "element stiffness": "stiffness_matrix_assembly",
        "btdb": "stiffness_matrix_assembly",
        "mass matrix": "mass_matrix",
        "consistent mass": "mass_matrix",
        "lumped mass": "mass_matrix",
        "load vector": "consistent_load_vector",
        "consistent load": "consistent_load_vector",
        "force vector": "consistent_load_vector",
        "body force vector": "consistent_load_vector",
        "jacobian matrix": "jacobian_matrix",
        "jacobian fea": "jacobian_matrix",
        "element jacobian": "jacobian_matrix",
        "b matrix": "b_matrix_strain_displacement",
        "b-matrix": "b_matrix_strain_displacement",
        "strain-displacement": "b_matrix_strain_displacement",
        "strain displacement matrix": "b_matrix_strain_displacement",
        "d matrix": "d_matrix_constitutive",
        "d-matrix": "d_matrix_constitutive",
        "constitutive matrix": "d_matrix_constitutive",
        "material matrix": "d_matrix_constitutive",
        "elasticity matrix": "d_matrix_constitutive",
        "plane stress matrix": "d_matrix_constitutive",
        "plane strain matrix": "d_matrix_constitutive",
        "von mises yield": "von_mises_yield",
        "von mises yield criterion": "von_mises_yield",
        "j2 plasticity": "von_mises_yield",
        "j2 flow theory": "von_mises_yield",
        "drucker-prager": "drucker_prager",
        "drucker prager": "drucker_prager",
        "dp criterion": "drucker_prager",
        "mohr-coulomb": "mohr_coulomb",
        "mohr coulomb": "mohr_coulomb",
        "coulomb friction": "mohr_coulomb",
        # --- NEW: Solvers ---
        "ilu": "ilu_preconditioner",
        "ilu(0)": "ilu_preconditioner",
        "ilu preconditioner": "ilu_preconditioner",
        "incomplete lu": "ilu_preconditioner",
        "ilut": "ilu_preconditioner",
        "multigrid": "multigrid",
        "multigrid method": "multigrid",
        "algebraic multigrid": "multigrid",
        "amg": "multigrid",
        "geometric multigrid": "multigrid",
        "v-cycle": "multigrid",
        "w-cycle": "multigrid",
        "arc-length": "arc_length_riks",
        "arc length": "arc_length_riks",
        "arc-length method": "arc_length_riks",
        "riks method": "arc_length_riks",
        "riks": "arc_length_riks",
        "crisfield": "arc_length_riks",
        "snap-through": "arc_length_riks",
        "line search": "line_search_armijo",
        "armijo": "line_search_armijo",
        "armijo line search": "line_search_armijo",
        "backtracking line search": "line_search_armijo",
        "sufficient decrease": "line_search_armijo",
        # --- NEW: Time Integration ---
        "central difference time": "explicit_central_difference",
        "explicit central difference": "explicit_central_difference",
        "explicit time integration": "explicit_central_difference",
        "bathe method": "bathe_method",
        "bathe time integration": "bathe_method",
        "bathe composite": "bathe_method",
        "generalized-alpha": "generalized_alpha",
        "generalized alpha": "generalized_alpha",
        "gen-alpha": "generalized_alpha",
        "chung-hulbert": "generalized_alpha",
        "bdf": "bdf_multistep",
        "backward differentiation": "bdf_multistep",
        "backward differentiation formula": "bdf_multistep",
        "bdf-2": "bdf_multistep",
        "bdf multistep": "bdf_multistep",
        "gear method": "bdf_multistep",
        # --- NEW: CFD ---
        "navier-stokes": "navier_stokes_incompressible",
        "navier stokes": "navier_stokes_incompressible",
        "incompressible ns": "navier_stokes_incompressible",
        "incompressible navier-stokes": "navier_stokes_incompressible",
        "ns equations": "navier_stokes_incompressible",
        "simple": "simple_algorithm",
        "simple algorithm": "simple_algorithm",
        "pressure-velocity coupling": "simple_algorithm",
        "patankar simple": "simple_algorithm",
        "piso": "piso_algorithm",
        "piso algorithm": "piso_algorithm",
        "pressure implicit": "piso_algorithm",
        "boussinesq": "boussinesq_approximation",
        "boussinesq approximation": "boussinesq_approximation",
        "buoyancy": "boussinesq_approximation",
        "natural convection": "boussinesq_approximation",
        "fractional step": "fractional_step_method",
        "fractional step method": "fractional_step_method",
        "chorin projection": "fractional_step_method",
        "projection method": "fractional_step_method",
        # --- NEW: Structural ---
        "euler-bernoulli": "euler_bernoulli_beam",
        "euler bernoulli": "euler_bernoulli_beam",
        "euler-bernoulli beam": "euler_bernoulli_beam",
        "beam bending": "euler_bernoulli_beam",
        "beam theory": "euler_bernoulli_beam",
        "timoshenko": "timoshenko_beam",
        "timoshenko beam": "timoshenko_beam",
        "thick beam": "timoshenko_beam",
        "shear deformation beam": "timoshenko_beam",
        "kirchhoff plate": "kirchhoff_plate",
        "kirchhoff": "kirchhoff_plate",
        "thin plate": "kirchhoff_plate",
        "plate bending": "kirchhoff_plate",
        "biharmonic plate": "kirchhoff_plate",
        "mindlin-reissner": "mindlin_reissner_plate",
        "mindlin reissner": "mindlin_reissner_plate",
        "mindlin plate": "mindlin_reissner_plate",
        "reissner plate": "mindlin_reissner_plate",
        "thick plate": "mindlin_reissner_plate",
        "buckling": "buckling_eigenvalue",
        "linear buckling": "buckling_eigenvalue",
        "buckling analysis": "buckling_eigenvalue",
        "eigenvalue buckling": "buckling_eigenvalue",
        "geometric stiffness": "buckling_eigenvalue",
        "modal analysis": "modal_analysis",
        "free vibration": "modal_analysis",
        "natural frequency": "modal_analysis",
        "eigenvalue vibration": "modal_analysis",
        "mode shapes": "modal_analysis",
        # --- NEW: Heat Transfer ---
        "fourier's law": "fourier_law",
        "fouriers law": "fourier_law",
        "fourier law": "fourier_law",
        "heat conduction": "fourier_law",
        "heat equation": "heat_equation",
        "transient conduction": "heat_equation",
        "thermal diffusion": "heat_equation",
        "heat conduction equation": "heat_equation",
        "newton cooling": "newton_cooling",
        "newton's cooling": "newton_cooling",
        "newtons cooling": "newton_cooling",
        "convective heat transfer": "newton_cooling",
        "stefan-boltzmann": "stefan_boltzmann_radiation",
        "stefan boltzmann": "stefan_boltzmann_radiation",
        "thermal radiation": "stefan_boltzmann_radiation",
        "radiative heat transfer": "stefan_boltzmann_radiation",
        "blackbody radiation": "stefan_boltzmann_radiation",
        "convection-diffusion": "convection_diffusion",
        "convection diffusion": "convection_diffusion",
        "advection-diffusion": "convection_diffusion",
        "advection diffusion": "convection_diffusion",
        "scalar transport": "convection_diffusion",
        # --- NEW: Statistics / Probability ---
        "normal distribution": "normal_distribution",
        "gaussian distribution": "normal_distribution",
        "gaussian pdf": "normal_distribution",
        "bell curve": "normal_distribution",
        "chi-squared": "chi_squared_distribution",
        "chi squared": "chi_squared_distribution",
        "chi2": "chi_squared_distribution",
        "chi-square distribution": "chi_squared_distribution",
        "student t": "student_t_distribution",
        "student's t": "student_t_distribution",
        "t-distribution": "student_t_distribution",
        "t distribution": "student_t_distribution",
        "t-test distribution": "student_t_distribution",
        "bayes theorem": "bayesian_update",
        "bayes' theorem": "bayesian_update",
        "bayesian": "bayesian_update",
        "bayesian update": "bayesian_update",
        "bayesian inference": "bayesian_update",
        "posterior update": "bayesian_update",
        "mle": "maximum_likelihood",
        "maximum likelihood": "maximum_likelihood",
        "maximum likelihood estimation": "maximum_likelihood",
        "log likelihood": "maximum_likelihood",
        # --- NEW: Optimization ---
        "lagrangian": "lagrangian_optimization",
        "lagrange multiplier": "lagrangian_optimization",
        "lagrangian optimization": "lagrangian_optimization",
        "constrained optimization": "lagrangian_optimization",
        "kkt": "kkt_conditions",
        "kkt conditions": "kkt_conditions",
        "karush-kuhn-tucker": "kkt_conditions",
        "karush kuhn tucker": "kkt_conditions",
        "penalty method": "penalty_method",
        "quadratic penalty": "penalty_method",
        "augmented lagrangian": "augmented_lagrangian",
        "method of multipliers": "augmented_lagrangian",
        "alm": "augmented_lagrangian",
        "interior point": "interior_point",
        "interior point method": "interior_point",
        "barrier method": "interior_point",
        "log barrier": "interior_point",
        "ipm": "interior_point",
        # --- NEW: Finance ---
        "heston": "heston_model",
        "heston model": "heston_model",
        "stochastic volatility": "heston_model",
        "heston stochastic vol": "heston_model",
        "vasicek": "vasicek_model",
        "vasicek model": "vasicek_model",
        "ornstein-uhlenbeck": "vasicek_model",
        "cir": "cir_model",
        "cir model": "cir_model",
        "cox-ingersoll-ross": "cir_model",
        "cox ingersoll ross": "cir_model",
        "bond pricing": "bond_pricing",
        "bond valuation": "bond_pricing",
        "discounted cash flow bond": "bond_pricing",
        "duration": "duration_convexity",
        "convexity": "duration_convexity",
        "duration and convexity": "duration_convexity",
        "macaulay duration": "duration_convexity",
        "modified duration": "duration_convexity",
        "markowitz": "markowitz_portfolio",
        "markowitz portfolio": "markowitz_portfolio",
        "mean-variance": "markowitz_portfolio",
        "mean variance optimization": "markowitz_portfolio",
        "portfolio optimization": "markowitz_portfolio",
        "efficient frontier": "markowitz_portfolio",
        # --- NEW: Numerical Methods ---
        "bisection": "bisection_method",
        "bisection method": "bisection_method",
        "binary search root": "bisection_method",
        "secant": "secant_method",
        "secant method": "secant_method",
        "thomas algorithm": "thomas_algorithm",
        "thomas": "thomas_algorithm",
        "tridiagonal solver": "thomas_algorithm",
        "tdma": "thomas_algorithm",
        "simpson": "simpson_rule",
        "simpson's rule": "simpson_rule",
        "simpsons rule": "simpson_rule",
        "simpson 1/3": "simpson_rule",
        "gauss-seidel": "gauss_seidel",
        "gauss seidel": "gauss_seidel",
        "successive overrelaxation": "gauss_seidel",
        "sor": "gauss_seidel",
        "jacobi": "jacobi_iteration",
        "jacobi iteration": "jacobi_iteration",
        "jacobi method": "jacobi_iteration",
        "jacobi solver": "jacobi_iteration",
        "lanczos": "lanczos_algorithm",
        "lanczos algorithm": "lanczos_algorithm",
        "lanczos iteration": "lanczos_algorithm",
        "arnoldi": "arnoldi_iteration",
        "arnoldi iteration": "arnoldi_iteration",
        "arnoldi process": "arnoldi_iteration",
        # --- NEW: ML / Deep Learning ---
        "dropout": "dropout_regularization",
        "dropout regularization": "dropout_regularization",
        "inverted dropout": "dropout_regularization",
        "residual connection": "residual_connection",
        "skip connection": "residual_connection",
        "resnet": "residual_connection",
        "shortcut connection": "residual_connection",
        "weight decay": "weight_decay_l2",
        "l2 regularization": "weight_decay_l2",
        "l2 penalty": "weight_decay_l2",
        "ridge penalty": "weight_decay_l2",
        "adamw": "weight_decay_l2",
        "cosine annealing": "learning_rate_cosine_decay",
        "cosine decay": "learning_rate_cosine_decay",
        "cosine lr": "learning_rate_cosine_decay",
        "cosine schedule": "learning_rate_cosine_decay",
        "sgdr": "learning_rate_cosine_decay",
        "warm restart": "learning_rate_cosine_decay",
        "positional encoding": "transformer_positional_encoding",
        "sinusoidal encoding": "transformer_positional_encoding",
        "transformer positional": "transformer_positional_encoding",
        "position embedding": "transformer_positional_encoding",
        # --- NEW: Linear Algebra ---
        "gram-schmidt": "gram_schmidt",
        "gram schmidt": "gram_schmidt",
        "orthogonalization": "gram_schmidt",
        "modified gram-schmidt": "gram_schmidt",
        "qr factorization": "qr_factorization",
        "qr decomposition": "qr_factorization",
        "householder qr": "qr_factorization",
        "givens rotation": "qr_factorization",
        "condition number": "condition_number",
        "cond(a)": "condition_number",
        "kappa": "condition_number",
        "ill-conditioned": "condition_number",
        "matrix condition": "condition_number",
        # --- NEW: DSP ---
        "kaiser": "kaiser_window",
        "kaiser window": "kaiser_window",
        "kaiser-bessel": "kaiser_window",
        "goertzel": "goertzel_algorithm",
        "goertzel algorithm": "goertzel_algorithm",
        "dtmf detection": "goertzel_algorithm",
        "single bin dft": "goertzel_algorithm",
        "z-transform": "z_transform",
        "z transform": "z_transform",
        "transfer function": "z_transform",
        "h(z)": "z_transform",
        "discrete transfer function": "z_transform",
    }

    for alias, template_key in _aliases.items():
        _NAME_TO_TEMPLATE[alias.lower()] = template_key


# Build the map at import time
_build_name_map()


# -----------------------------------------------------------------------
# FormulaReconstructor
# -----------------------------------------------------------------------

class FormulaReconstructor:
    """Tespit edilen algoritmalari formul sablonlarina esler.

    AlgorithmMatch.name degerini normalize ederek FORMULA_TEMPLATES'teki
    uygun sablonu bulur.  Bulunamazsa fuzzy matching dener (substring).
    """

    def reconstruct(
        self, algorithms: list[AlgorithmMatch],
    ) -> list[FormulaInfo]:
        """Map detected algorithms to formula templates.

        Args:
            algorithms: Tespit edilen algoritma listesi
                (EngineeringAlgorithmAnalyzer ciktisi).

        Returns:
            Eslesen FormulaInfo listesi.  Formulu olmayan algoritmalar
            atlanir (kripto vb. engineering formulu yok).
        """
        results: list[FormulaInfo] = []
        seen: set[str] = set()  # Avoid duplicate formulas

        for algo in algorithms:
            template_key = self._match_template(algo.name)
            if template_key is None:
                continue
            if template_key in seen:
                continue
            seen.add(template_key)

            template = FORMULA_TEMPLATES[template_key]
            results.append(template)

        return results

    def generate_report(self, formulas: list[FormulaInfo]) -> str:
        """Generate markdown report section.

        Tespit edilen her formul icin:
        - Algoritma adi ve method aciklamasi
        - ASCII formul
        - LaTeX formul (katex/mathjax uyumlu)
        - Parametreler (varsa)
        - Referans

        Args:
            formulas: reconstruct() ciktisi.

        Returns:
            Markdown formatinda rapor string'i.
        """
        if not formulas:
            return "## Detected Engineering Formulas\n\nNo engineering formulas detected.\n"

        lines: list[str] = [
            "## Detected Engineering Formulas",
            "",
            f"**Total:** {len(formulas)} formula(s) identified.",
            "",
        ]

        for i, f in enumerate(formulas, 1):
            lines.append(f"### {i}. {f.algorithm}")
            lines.append("")
            lines.append(f"**Method:** {f.method}")
            lines.append("")
            lines.append("**Formula (ASCII):**")
            lines.append(f"```")
            lines.append(f"{f.ascii}")
            lines.append(f"```")
            lines.append("")
            lines.append("**Formula (LaTeX):**")
            lines.append(f"$$")
            lines.append(f"{f.latex}")
            lines.append(f"$$")
            lines.append("")

            if f.parameters:
                lines.append("**Parameters:**")
                lines.append("")
                lines.append("| Parameter | Value |")
                lines.append("|-----------|-------|")
                for param, value in f.parameters.items():
                    lines.append(f"| `{param}` | {value} |")
                lines.append("")

            lines.append(f"**Reference:** {f.reference}")
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal matching
    # ------------------------------------------------------------------

    @staticmethod
    def _match_template(algo_name: str) -> str | None:
        """Algoritma adini sablon anahtarina esle.

        1. Exact match (normalized lowercase)
        2. Alias lookup (_NAME_TO_TEMPLATE)
        3. Substring fuzzy match (en uzun eslesen alias)

        Returns:
            Template key or None.
        """
        normalized = algo_name.lower().strip()

        # 1. Direct template key match
        if normalized in FORMULA_TEMPLATES:
            return normalized

        # 2. Alias lookup
        if normalized in _NAME_TO_TEMPLATE:
            return _NAME_TO_TEMPLATE[normalized]

        # 3. Fuzzy substring match -- algo_name icinde bir alias var mi?
        #    En uzun eslesen alias tercih edilir (specificity).
        best_key: str | None = None
        best_len = 0
        for alias, template_key in _NAME_TO_TEMPLATE.items():
            if alias in normalized and len(alias) > best_len:
                best_key = template_key
                best_len = len(alias)

        if best_key is not None:
            return best_key

        # 4. Ters yonde: normalized, bir alias'in icinde mi?
        for alias, template_key in _NAME_TO_TEMPLATE.items():
            if normalized in alias and len(normalized) >= 3:
                return template_key

        return None
