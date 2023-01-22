using System;
using System.Linq;

// Original by Jared Atkinson (@jaredcatkinson)
// ported to C# by https://github.com/DaFuqs
public class LevenshteinDistance {

	public static int Measure(string original, string modified) {
		if (original == modified) {
			return 0;
        }

		int lorig = original.Length;
		int ldiff = modified.Length;
		if (lorig == 0 || ldiff == 0) {
			return lorig == 0 ? ldiff : lorig;
        }

		var matrix = new int[lorig + 1, ldiff + 1];

		for (int i = 1; i <= lorig; i++) {
			matrix[i, 0] = i;
			for (int j = 1; j <= ldiff; j++) {
				int cost = modified[j - 1] == original[i - 1] ? 0 : 1;
				if (i == 1)
					matrix[0, j] = j;

				int[] vals = new int[] {
					matrix[i - 1, j    ] + 1,
					matrix[i    , j - 1] + 1,
					matrix[i - 1, j - 1] + cost
				};
				matrix[i,j] = vals.Min();
				if (i > 1 && j > 1 && original[i - 1] == modified[j - 2] && original[i - 2] == modified[j - 1])
					matrix[i,j] = Math.Min (matrix[i,j], matrix[i - 2, j - 2] + cost);
			}
		}
		return matrix[lorig, ldiff];
	}
}