# File: evosolve_gp.py
# This is the Python "muscle" that Node.js will call.
# You must install any needed packages, e.g., pip install pandas gplearn

import pandas as pd
from gplearn.genetic import SymbolicRegressor
from sklearn.metrics import r2_score
import numpy as np

def run_gp_analysis(csv_path, output_column, active_operators):
    """
    Runs the Genetic Programming analysis.
    This function is called by the Node.js backend.
    """
    try:
        # 1. Load data
        data = pd.read_csv(csv_path)
        
        # 2. Separate inputs (X) and output (y)
        y = data[output_column].values
        input_columns = [col for col in data.columns if col != output_column]
        X = data[input_columns].values
        
        # 3. Configure the GP
        # The 'function_set' is the key part that uses the Node.js input
        gp = SymbolicRegressor(
            population_size=1000,
            generations=20,
            stopping_criteria=0.95, # Stop if accuracy is good
            function_set=tuple(active_operators), # e.g., ('add', 'sub', 'mul', 'div')
            parsimony_coefficient=0.01, # Helps control bloat
            verbose=0,
            random_state=1
        )
        
        # 4. Run the "muscle" (the GP search)
        gp.fit(X, y)
        
        # 5. Get results
        best_formula_str = str(gp._program)
        
        # Calculate accuracy (R-squared)
        y_pred = gp.predict(X)
        accuracy = 0.0
        if not np.any(np.isnan(y_pred)) and not np.any(np.isinf(y_pred)):
             accuracy = r2_score(y, y_pred)
        
        # Check for bloat (e.g., if the formula is very long)
        # This is a simple example; your logic might be more complex
        is_bloated = len(best_formula_str) > 75 # Example threshold
        
        # 6. Return results as a dictionary (will be converted to JSON)
        return {
            "formula": best_formula_str,
            "accuracy_score": float(accuracy),
            "is_bloated": is_bloated,
            "operators_used": active_operators
        }

    except Exception as e:
        # Return a structured error
        return {
            "error": str(e),
            "formula": "Error",
            "accuracy_score": 0.0,
            "is_bloated": True
        }