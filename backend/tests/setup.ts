import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

// Test database setup
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/vulnerable_webapp_test'
    }
  }
});

// Global test users for consistent testing
export const testUsers = {
  user1: {
    email: 'user1@test.com',
    password: 'password123',
    firstName: 'Test',
    lastName: 'User1'
  },
  user2: {
    email: 'user2@test.com',
    password: 'password123',
    firstName: 'Test',
    lastName: 'User2'
  },
  admin: {
    email: 'admin@test.com',
    password: 'admin123',
    firstName: 'Admin',
    lastName: 'User'
  }
};

// Setup and teardown functions
export const setupTestDatabase = async () => {
  // Clean database
  await prisma.comment.deleteMany();
  await prisma.task.deleteMany();
  await prisma.user.deleteMany();

  // Create test users
  const hashedPassword = await bcrypt.hash('password123', 10);
  const adminPassword = await bcrypt.hash('admin123', 10);

  const createdUsers = await Promise.all([
    prisma.user.create({
      data: {
        email: testUsers.user1.email,
        passwordHash: hashedPassword,
        firstName: testUsers.user1.firstName,
        lastName: testUsers.user1.lastName,
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: testUsers.user2.email,
        passwordHash: hashedPassword,
        firstName: testUsers.user2.firstName,
        lastName: testUsers.user2.lastName,
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: testUsers.admin.email,
        passwordHash: adminPassword,
        firstName: testUsers.admin.firstName,
        lastName: testUsers.admin.lastName,
        emailVerified: true
      }
    })
  ]);

  return {
    user1: createdUsers[0],
    user2: createdUsers[1],
    admin: createdUsers[2]
  };
};

export const cleanupTestDatabase = async () => {
  await prisma.comment.deleteMany();
  await prisma.task.deleteMany();
  await prisma.user.deleteMany();
};

// Global setup and teardown
beforeAll(async () => {
  await setupTestDatabase();
});

afterAll(async () => {
  await cleanupTestDatabase();
  await prisma.$disconnect();
});

export { prisma };