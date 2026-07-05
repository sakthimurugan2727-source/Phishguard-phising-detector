#include<stdio.h>

struct employee{
  int eid;
  char name[20];
  int exp;
};

int main(){
  struct employee e[30];
  printf("Enter details of employee: ");
  scanf("%d",&e.eid);
  scanf("%s",e.name);
  scanf("%d",&e.exp);

  printf("Name: %s\n",e.name);
  printf("EmployeeId: %d\n",e.eid);
  printf("Exp: %d\n",e.exp);
}