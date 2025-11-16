import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import postgres from 'postgres';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`
      SELECT * FROM users WHERE email = ${email}
    `;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) {
          console.log('Invalid credentials (zod)');
          return null;
        }

        const { email, password } = parsedCredentials.data;

        const user = await getUser(email);
        if (!user) {
          console.log('No user found for email', email);
          return null;
        }

        // 🔴 CHANGE IS HERE: plain-text comparison
        if (user.password !== password) {
          console.log('Password mismatch');
          return null;
        }

        // ✅ NextAuth just needs an object with at least id / name / email
        return {
          id: user.id,
          name: user.name,
          email: user.email,
        };
      },
    }),
  ],
});
