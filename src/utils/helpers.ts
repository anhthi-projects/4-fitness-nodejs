import * as bcrypt from 'bcrypt';

export const hasData = (input: string): Promise<string> =>
  bcrypt.hash(input, 10);
